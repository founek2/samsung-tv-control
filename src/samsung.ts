import { exec } from 'child_process'
import * as fs from 'fs'
import * as net from 'net'
import * as path from 'path'
import * as request from 'request'
import * as wol from 'wake_on_lan'
import { client as WebSocket, connection } from 'websocket'
import { KEYS } from './keys'
import Logger from './logger'
import { Configuration, WSData, App, Command } from './types'
import {
  base64,
  chr,
  getVideoId,
  getMsgInstalledApp,
  getMsgAppIcon,
  getMsgLaunchApp,
  getCommandByKey,
  getSendTextCommand,
} from './helpers'
import EventEmitter = require('events')

class Samsung extends EventEmitter {
  private IP: string
  private MAC: string
  private PORT: number
  private APP_STRING: string
  private TV_APP_STRING: string
  private TOKEN: string
  private NAME_APP: string
  private LOGGER: Logger
  private SAVE_TOKEN: boolean
  private TOKEN_FILE = path.join(__dirname, 'token.txt')
  private WS_URL: string
  private ws: WebSocket
  private connection?: connection

  constructor(config: Configuration) {
    super();

    if (!config.ip) {
      throw new Error('You must provide IP in config')
    }

    if (!config.mac) {
      throw new Error('You must provide MAC in config')
    }

    this.IP = config.ip
    this.MAC = config.mac
    this.PORT = Number(config.port) || 8002
    this.TOKEN = config.token || ''
    this.NAME_APP = Buffer.from(config.nameApp || 'NodeJS Remote').toString('base64')
    this.SAVE_TOKEN = config.saveToken || false
    // legacy 55000
    this.APP_STRING = config.appString || 'iphone..iapp.samsung'
    this.TV_APP_STRING = config.tvAppString || 'iphone.UE40NU7400.iapp.samsung'

    this.LOGGER = new Logger({ DEBUG_MODE: !!config.debug })

    this.LOGGER.log('config', config, 'constructor')

    if (this.SAVE_TOKEN) {
      this.TOKEN = this._getTokenFromFile() || ''
    }
    this.WS_URL = this._getWSUrl()

    this.ws = new WebSocket({ tlsOptions: { rejectUnauthorized: false } });

    this.LOGGER.log(
      'internal config',
      {
        IP: this.IP,
        MAC: this.MAC,
        NAME_APP: this.NAME_APP,
        PORT: this.PORT,
        SAVE_TOKEN: this.SAVE_TOKEN,
        TOKEN: this.TOKEN,
        WS_URL: this.WS_URL,
      },
      'constructor',
    )

    this.connect();
  }

  public getToken(done: (token: string | null) => void) {
    this.LOGGER.log('getToken', '')

    if (this.SAVE_TOKEN && this.TOKEN !== 'null' && this.TOKEN !== '') {
      done(this.TOKEN)
      return
    }

    this.sendKey(KEYS.KEY_HOME, (err, res) => {
      if (err) {
        this.LOGGER.error('after sendKey', err, 'getToken')
        throw new Error('Error send Key')
      }

      const token = (res && typeof res !== 'string' && res.data && res.data.token && res.data.token) || null

      if (token !== null) {
        const sToken = String(token)
        this.LOGGER.log('got token', sToken, 'getToken')
        this.TOKEN = sToken
        this.WS_URL = this._getWSUrl()

        if (this.SAVE_TOKEN) {
          this._saveTokenToFile(sToken)
        }

        done(sToken)
        return
      }

      done(null)
    })
  }

  public getTokenPromise(): Promise<string> {
    return new Promise((resolve, reject) => {
      this.getToken((token) => {
        if (token) {
          resolve(token)
        } else {
          reject(new Error('Did not receive token from Samsung TV'))
        }
      })
    })
  }

  public setToken(token: string) {
    this.TOKEN = token
    this.WS_URL = this._getWSUrl()
  }

  public sendKey(
    key: KEYS,
    done?: (err: Error | { code: string } | null, res: WSData | string | null) => void,
  ) {
    this.LOGGER.log('send key', key, 'sendKey')
    if (this.PORT === 55000) {
      this._sendLegacy(key, done)
    } else {
      this._send(getCommandByKey(key), done, 'ms.channel.connect')
    }
  }

  public sendKeyPromise(key: KEYS) {
    this.LOGGER.log('send key', key, 'sendKeyPromise')
    if (this.PORT === 55000) {
      return this._sendLegacyPromise(key)
    } else {
      return this._sendPromise(getCommandByKey(key), 'ms.channel.connect')
    }
  }

  public sendText(
    text: string,
    done?: (err: Error | { code: string } | null, res: WSData | string | null) => void,
  ) {
    this.LOGGER.log('send text', text, 'sendText')
    if (this.PORT === 55000) {
      this.LOGGER.error('send text not supported in legacy api', 'send text not supported', 'send text error')
      return false
    } else {
      this._send(getSendTextCommand(text), done, 'ms.channel.connect')
    }
  }

  public sendTextPromise(text: string) {
    this.LOGGER.log('send text', text, 'sendTextPromise')
    if (this.PORT === 55000) {
      this.LOGGER.error('send text not supported in legacy api', 'send text not supported', 'send text error')
      return false
    } else {
      return this._sendPromise(getSendTextCommand(text), 'ms.channel.connect')
    }
  }

  public getAppsFromTV(done?: (err: Error | { code: string } | null, res: WSData | string | null) => void) {
    return this._send(getMsgInstalledApp(), done)
  }

  public getAppsFromTVPromise(): Promise<WSData | null> {
    return this._sendPromise(getMsgInstalledApp())
  }

  public getAppIcon(
    iconPath: string,
    done?: (err: Error | { code: string } | null, res: WSData | string | null) => void,
  ) {
    return this._send(getMsgAppIcon(iconPath), done)
  }

  public getAppIconPromise(iconPath: string): Promise<WSData | null> {
    return this._sendPromise(getMsgAppIcon(iconPath))
  }

  public openAppByAppIdAndType(
    appId: string,
    type: number,
    done?: (error: Error | { code: string } | null, result: WSData | null) => void,
  ) {
    this._send(getMsgLaunchApp({ app_type: type, appId, icon: '', is_lock: 0, name: '' }), done)
  }

  public openAppByAppIdAndTypePromise(appId: string, type: number) {
    return new Promise<WSData | null>((resolve, reject) => {
      this.openAppByAppIdAndType(appId, type, (err, res) => {
        if (err) {
          reject(err)
        }

        resolve(res)
      })
    })
  }

  public openApp(
    appId: string,
    done?: (err: Error | { code: string } | null, res: WSData | string | null) => void,
  ) {
    this.getAppsFromTV((err, res) => {
      this.LOGGER.error('getAppsFromTV error', String(err), 'openApp getAppsFromTV')
      if (
        err ||
        (res && typeof res !== 'string' && res.data && res.data.data && res.data.data === undefined)
      ) {
        this.LOGGER.error('getAppsFromTV error', String(err), 'openApp getAppsFromTV')
        return false
      }

      const apps: App[] = res && typeof res !== 'string' && res.data && res.data.data ? res.data.data : []
      const app = apps.find((appIter) => appIter.appId === appId)

      if (!app) {
        this.LOGGER.error('This APP is not installed', { appId, app }, 'openApp getAppsFromTV')
        if (done) {
          done(new Error('This APP is not installed'), null);
        }
      } else {
        this._send(getMsgLaunchApp(app), done)
      }
    })
  }

  public async openAppPromise(appId: string) {
    return new Promise((resolve, reject) => {
      this.openApp(appId, (err, res) => {
        if (!err) {
          resolve(res)
        } else {
          reject(err)
        }
      })
    })
  }

  public openYouTubeLink(url: string) {
    const videoId = getVideoId(url)
    if (!videoId) {
      return false
    }

    this.LOGGER.log('videoId', { videoId }, 'openYouTubeLink')

    return new Promise((resolve, reject) => {
      request.post(
        'http://' + this.IP + ':8080/ws/apps/YouTube',
        {
          headers: {
            'Content-Type': 'text/plain',
            'Content-Length': Buffer.byteLength(videoId),
          },
          timeout: 10000,
          body: videoId,
        },
        (err, response) => {
          if (!err) {
            this.LOGGER.log(
              'Link sent',
              { status: response.statusCode, body: response.body, headers: response.headers },
              'openYouTubeLink',
            )
            resolve('Link sent')
          } else {
            this.LOGGER.error('While send a link, somthing went wrong', { err }, 'openYouTubeLink')
            reject(err)
          }
        },
      )
    })
  }

  public isAvailable(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      request.get(
        { url: `http://${this.IP}:8001${this.PORT === 55000 ? '/ms/1.0/' : '/api/v2/'}`, timeout: 3000 },
        (err: Error, res: request.RequestResponse) => {
          if (err) {
            return reject(err)
          }

          if (!err && res.statusCode === 200) {
            this.LOGGER.log(
              'TV is available',
              { body: res.body as string, code: res.statusCode },
              'isAvailable',
            )

            resolve(true)
          } else {
            this.LOGGER.error('TV is not available', { err }, 'isAvailable')
            resolve(false)
          }
        },
      )
    })
  }

  public isAvailablePing(): Promise<boolean> {
    return new Promise((resolve) => {
      exec('ping -c 1 -W 1 ' + this.IP, (error, stdout, _) => {
        if (error) {
          this.LOGGER.error('TV is not available', { error }, 'isAvailable')
          // Do not reject since we're testing for the TV to be available
          resolve(false)
        } else {
          this.LOGGER.log('TV is available', { stdout }, 'isAvailable')
          resolve(true)
        }
      })
    })
  }

  public turnOn(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      wol.wake(this.MAC, { num_packets: 30 }, (err: Error) => {
        if (err) {
          this.LOGGER.error('Fail turn on', err, 'turnOn')
          reject(err)
        } else {
          this.LOGGER.log('WOL sent command to TV', '', 'turnOn')
          resolve(true)
        }
      })
    })
  }

  public getLogs() {
    this.LOGGER.saveLogToFile()
  }

  /**
   * If you don't need to keep connection, you can to close immediately
   */
  public closeConnection() {
    // backward compatibility
  }

  private reconnect() {
    this.LOGGER.log('connecting to ' + this.WS_URL, '');
    this.ws.connect(this.WS_URL);
  }

  public ready(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.on('ready', () => resolve())
    });
  }

  private connect() {
    this.reconnect();

    this.ws.on('connect', (connection) => {
      this.LOGGER.log('connected', 'ws.on connect');
      this.connection = connection;
      this.emit('connect')

      connection.on('message', (message) => {
        if (message.type != "utf8") return;
        const data: WSData = JSON.parse(message.utf8Data);
        this.emit('data', data)

        this.LOGGER.log('data: ', JSON.stringify(data, null, 2), 'ws.on message')

        if (data.event !== 'ms.channel.connect') {
          this.LOGGER.log('if not correct event', JSON.stringify(data, null, 2), 'ws.on message')
        }

        if (data.event == "ms.channel.connect") {
          this.emit('ready');

          const token = data?.data?.token;
          if (token) {
            const sToken = String(token)
            this.LOGGER.log('got token', sToken, 'getToken')
            this.TOKEN = sToken
            this.WS_URL = this._getWSUrl()

            if (this.SAVE_TOKEN) {
              this._saveTokenToFile(sToken)
            }

            connection.close();
          }
        }
      })

      connection.on('close', () => {
        this.emit('close')
        this.LOGGER.log('', '', 'ws.on close');
        setTimeout(() => this.reconnect(), 1000);
      })

      connection.on('error', (err) => {
        let errorMsg = ''
        if (err.message === 'EHOSTUNREACH' || err.message === 'ECONNREFUSED') {
          errorMsg = 'TV is off or unavailable'
        }
        console.error(errorMsg, err)
        this.LOGGER.error(errorMsg, err, 'ws.on error')
      })
    })
  }

  private _send(
    command: Command,
    done?: (err: null | (Error), res: WSData | null) => void,
    eventHandle?: string,
  ) {
    if (this.connection?.state != 'open') return;

    function rejected(err?: Error) {
      if (done && err) done(err, null);
    }

    if (done) {
      let timeout = setTimeout(() => {
        this.removeListener('data', listener);
        done(null, null)
      }, 3000);

      const listener = (d: WSData) => {
        clearTimeout(timeout);
        this.removeListener('data', listener)
        done(null, d);
      }
      this.on('data', listener);
    }

    this.LOGGER.log('sending cmd', '');
    this.connection?.send(JSON.stringify(command), rejected);
  }

  private _sendPromise(command: Command, eventHandle?: string): Promise<WSData | null> {
    return new Promise((resolve, reject) => {
      this._send(
        command,
        (err, res) => {
          if (err) {
            reject(err)
          } else {
            resolve(res)
          }
        },
        eventHandle,
      )
    })
  }

  private _sendLegacy(key: KEYS, done?: (err: null | Error | { code: string }, res: string) => void) {
    if (!key) {
      this.LOGGER.error('send() missing command', { key })
      return
    }

    this.LOGGER.log('send key', key, 'sendKey')

    const connection = net.connect(this.PORT, this.IP)
    connection.setTimeout(3000)

    connection.on('connect', () => {
      const payload = this.getLegacyCommand(key)
      connection.write(payload.header)
      connection.write(payload.command)
      connection.end()
      connection.destroy()
      if (done) {
        done(null, key)
      }
    })

    connection.on('close', () => {
      this.LOGGER.log('closed connection', {}, 'connection.on close')
    })

    connection.on('error', (err: Error & { code: string }) => {
      let errorMsg = ''

      if (err.code === 'EHOSTUNREACH' || err.code === 'ECONNREFUSED') {
        errorMsg = 'Device is off or unreachable'
      } else {
        errorMsg = err.code
      }

      console.error(errorMsg)
      this.LOGGER.error(errorMsg, err, 'connection.on error')
      if (done) {
        done(err, key)
      }
    })

    connection.on('timeout', (err: Error) => {
      console.error('timeout')
      this.LOGGER.error('timeout', err, 'connection.on timeout')
      if (done) {
        done(err, key)
      }
    })
  }

  private _sendLegacyPromise(key: KEYS) {
    return new Promise((resolve, reject) => {
      this._sendLegacy(key, (err, res) => {
        if (err) {
          reject(err)
        } else {
          resolve(res)
        }
      })
    })
  }

  private getLegacyCommand(key: KEYS) {
    const payload = { header: '', command: '' }

    const headerData =
      chr(0x64) +
      chr(0x00) +
      chr(base64(this.IP).length) +
      chr(0x00) +
      base64(this.IP) +
      chr(base64(this.MAC).length) +
      chr(0x00) +
      base64(this.MAC) +
      chr(base64(this.NAME_APP).length) +
      chr(0x00) +
      base64(this.NAME_APP)

    payload.header =
      chr(0x00) +
      chr(this.APP_STRING.length) +
      chr(0x00) +
      this.APP_STRING +
      chr(headerData.length) +
      chr(0x00) +
      headerData

    const commandData = chr(0x00) + chr(0x00) + chr(0x00) + chr(base64(key).length) + chr(0x00) + base64(key)

    payload.command =
      chr(0x00) +
      chr(this.TV_APP_STRING.length) +
      chr(0x00) +
      this.TV_APP_STRING +
      chr(commandData.length) +
      chr(0x00) +
      commandData

    return payload
  }

  private _saveTokenToFile(token: string) {
    try {
      fs.writeFileSync(this.TOKEN_FILE, token)
      console.log('Token saved!')
    } catch (err) {
      console.log('File error!')
      this.LOGGER.error('catch fil esave', { err }, '_saveTokenToFile')
    }
  }

  private _getTokenFromFile(): string | null {
    try {
      fs.accessSync(this.TOKEN_FILE, fs.constants.F_OK)
      console.log('File suss!')
      const fileData = fs.readFileSync(this.TOKEN_FILE)
      return fileData.toString()
    } catch (err) {
      console.log('File error!')
      this.LOGGER.error('if (this.SAVE_TOKEN)', { err }, 'constructor')
      return null
    }
  }

  private _getWSUrl() {
    return `${this.PORT === 8001 ? 'ws' : 'wss'}://${this.IP}:${this.PORT
      }/api/v2/channels/samsung.remote.control?name=${this.NAME_APP}${this.TOKEN !== '' ? `&token=${this.TOKEN}` : ''
      }`
  }
}

export default Samsung

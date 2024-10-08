"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const child_process_1 = require("child_process");
const fs = require("fs");
const net = require("net");
const path = require("path");
const request = require("request");
const wol = require("wake_on_lan");
const websocket_1 = require("websocket");
const keys_1 = require("./keys");
const logger_1 = require("./logger");
const helpers_1 = require("./helpers");
const EventEmitter = require("events");
class Samsung extends EventEmitter {
    IP;
    MAC;
    PORT;
    APP_STRING;
    TV_APP_STRING;
    TOKEN;
    NAME_APP;
    LOGGER;
    SAVE_TOKEN;
    TOKEN_FILE = path.join(__dirname, 'token.txt');
    WS_URL;
    ws;
    connection;
    constructor(config) {
        super();
        if (!config.ip) {
            throw new Error('You must provide IP in config');
        }
        if (!config.mac) {
            throw new Error('You must provide MAC in config');
        }
        this.IP = config.ip;
        this.MAC = config.mac;
        this.PORT = Number(config.port) || 8002;
        this.TOKEN = config.token || '';
        this.NAME_APP = Buffer.from(config.nameApp || 'NodeJS Remote').toString('base64');
        this.SAVE_TOKEN = config.saveToken || false;
        this.APP_STRING = config.appString || 'iphone..iapp.samsung';
        this.TV_APP_STRING = config.tvAppString || 'iphone.UE40NU7400.iapp.samsung';
        this.LOGGER = new logger_1.default({ DEBUG_MODE: !!config.debug });
        this.LOGGER.log('config', config, 'constructor');
        if (this.SAVE_TOKEN) {
            this.TOKEN = this._getTokenFromFile() || '';
        }
        this.WS_URL = this._getWSUrl();
        this.ws = new websocket_1.client({ tlsOptions: { rejectUnauthorized: false } });
        this.LOGGER.log('internal config', {
            IP: this.IP,
            MAC: this.MAC,
            NAME_APP: this.NAME_APP,
            PORT: this.PORT,
            SAVE_TOKEN: this.SAVE_TOKEN,
            TOKEN: this.TOKEN,
            WS_URL: this.WS_URL,
        }, 'constructor');
        this.connect();
    }
    getToken(done) {
        this.LOGGER.log('getToken', '');
        if (this.SAVE_TOKEN && this.TOKEN !== 'null' && this.TOKEN !== '') {
            done(this.TOKEN);
            return;
        }
        this.sendKey(keys_1.KEYS.KEY_HOME, (err, res) => {
            if (err) {
                this.LOGGER.error('after sendKey', err, 'getToken');
                throw new Error('Error send Key');
            }
            const token = (res && typeof res !== 'string' && res.data && res.data.token && res.data.token) || null;
            if (token !== null) {
                const sToken = String(token);
                this.LOGGER.log('got token', sToken, 'getToken');
                this.TOKEN = sToken;
                this.WS_URL = this._getWSUrl();
                if (this.SAVE_TOKEN) {
                    this._saveTokenToFile(sToken);
                }
                done(sToken);
                return;
            }
            done(null);
        });
    }
    getTokenPromise() {
        return new Promise((resolve, reject) => {
            this.getToken((token) => {
                if (token) {
                    resolve(token);
                }
                else {
                    reject(new Error('Did not receive token from Samsung TV'));
                }
            });
        });
    }
    setToken(token) {
        this.TOKEN = token;
        this.WS_URL = this._getWSUrl();
    }
    sendKey(key, done) {
        this.LOGGER.log('send key', key, 'sendKey');
        if (this.PORT === 55000) {
            this._sendLegacy(key, done);
        }
        else {
            this._send(helpers_1.getCommandByKey(key), done, 'ms.channel.connect');
        }
    }
    sendKeyPromise(key) {
        this.LOGGER.log('send key', key, 'sendKeyPromise');
        if (this.PORT === 55000) {
            return this._sendLegacyPromise(key);
        }
        else {
            return this._sendPromise(helpers_1.getCommandByKey(key), 'ms.channel.connect');
        }
    }
    sendText(text, done) {
        this.LOGGER.log('send text', text, 'sendText');
        if (this.PORT === 55000) {
            this.LOGGER.error('send text not supported in legacy api', 'send text not supported', 'send text error');
            return false;
        }
        else {
            this._send(helpers_1.getSendTextCommand(text), done, 'ms.channel.connect');
        }
    }
    sendTextPromise(text) {
        this.LOGGER.log('send text', text, 'sendTextPromise');
        if (this.PORT === 55000) {
            this.LOGGER.error('send text not supported in legacy api', 'send text not supported', 'send text error');
            return false;
        }
        else {
            return this._sendPromise(helpers_1.getSendTextCommand(text), 'ms.channel.connect');
        }
    }
    getAppsFromTV(done) {
        return this._send(helpers_1.getMsgInstalledApp(), done);
    }
    getAppsFromTVPromise() {
        return this._sendPromise(helpers_1.getMsgInstalledApp());
    }
    getAppIcon(iconPath, done) {
        return this._send(helpers_1.getMsgAppIcon(iconPath), done);
    }
    getAppIconPromise(iconPath) {
        return this._sendPromise(helpers_1.getMsgAppIcon(iconPath));
    }
    openAppByAppIdAndType(appId, type, done) {
        this._send(helpers_1.getMsgLaunchApp({ app_type: type, appId, icon: '', is_lock: 0, name: '' }), done);
    }
    openAppByAppIdAndTypePromise(appId, type) {
        return new Promise((resolve, reject) => {
            this.openAppByAppIdAndType(appId, type, (err, res) => {
                if (err) {
                    reject(err);
                }
                resolve(res);
            });
        });
    }
    openApp(appId, done) {
        this.getAppsFromTV((err, res) => {
            this.LOGGER.error('getAppsFromTV error', String(err), 'openApp getAppsFromTV');
            if (err ||
                (res && typeof res !== 'string' && res.data && res.data.data && res.data.data === undefined)) {
                this.LOGGER.error('getAppsFromTV error', String(err), 'openApp getAppsFromTV');
                return false;
            }
            const apps = res && typeof res !== 'string' && res.data && res.data.data ? res.data.data : [];
            const app = apps.find((appIter) => appIter.appId === appId);
            if (!app) {
                this.LOGGER.error('This APP is not installed', { appId, app }, 'openApp getAppsFromTV');
                if (done) {
                    done(new Error('This APP is not installed'), null);
                }
            }
            else {
                this._send(helpers_1.getMsgLaunchApp(app), done);
            }
        });
    }
    async openAppPromise(appId) {
        return new Promise((resolve, reject) => {
            this.openApp(appId, (err, res) => {
                if (!err) {
                    resolve(res);
                }
                else {
                    reject(err);
                }
            });
        });
    }
    openYouTubeLink(url) {
        const videoId = helpers_1.getVideoId(url);
        if (!videoId) {
            return false;
        }
        this.LOGGER.log('videoId', { videoId }, 'openYouTubeLink');
        return new Promise((resolve, reject) => {
            request.post('http://' + this.IP + ':8080/ws/apps/YouTube', {
                headers: {
                    'Content-Type': 'text/plain',
                    'Content-Length': Buffer.byteLength(videoId),
                },
                timeout: 10000,
                body: videoId,
            }, (err, response) => {
                if (!err) {
                    this.LOGGER.log('Link sent', { status: response.statusCode, body: response.body, headers: response.headers }, 'openYouTubeLink');
                    resolve('Link sent');
                }
                else {
                    this.LOGGER.error('While send a link, somthing went wrong', { err }, 'openYouTubeLink');
                    reject(err);
                }
            });
        });
    }
    isAvailable() {
        return new Promise((resolve, reject) => {
            request.get({ url: `http://${this.IP}:8001${this.PORT === 55000 ? '/ms/1.0/' : '/api/v2/'}`, timeout: 3000 }, (err, res) => {
                if (err) {
                    return reject(err);
                }
                if (!err && res.statusCode === 200) {
                    this.LOGGER.log('TV is available', { body: res.body, code: res.statusCode }, 'isAvailable');
                    resolve(true);
                }
                else {
                    this.LOGGER.error('TV is not available', { err }, 'isAvailable');
                    resolve(false);
                }
            });
        });
    }
    isAvailablePing() {
        return new Promise((resolve) => {
            child_process_1.exec('ping -c 1 -W 1 ' + this.IP, (error, stdout, _) => {
                if (error) {
                    this.LOGGER.error('TV is not available', { error }, 'isAvailable');
                    resolve(false);
                }
                else {
                    this.LOGGER.log('TV is available', { stdout }, 'isAvailable');
                    resolve(true);
                }
            });
        });
    }
    turnOn() {
        return new Promise((resolve, reject) => {
            wol.wake(this.MAC, { num_packets: 30 }, (err) => {
                if (err) {
                    this.LOGGER.error('Fail turn on', err, 'turnOn');
                    reject(err);
                }
                else {
                    this.LOGGER.log('WOL sent command to TV', '', 'turnOn');
                    resolve(true);
                }
            });
        });
    }
    getLogs() {
        this.LOGGER.saveLogToFile();
    }
    closeConnection() {
    }
    reconnect() {
        this.LOGGER.log('connecting to ' + this.WS_URL, '');
        this.ws.connect(this.WS_URL);
    }
    ready() {
        return new Promise((resolve, reject) => {
            this.on('ready', () => resolve());
        });
    }
    connect() {
        this.reconnect();
        this.ws.on('connect', (connection) => {
            this.LOGGER.log('connected', 'ws.on connect');
            this.connection = connection;
            this.emit('connect');
            connection.on('message', (message) => {
                if (message.type != "utf8")
                    return;
                const data = JSON.parse(message.utf8Data);
                this.emit('data', data);
                this.LOGGER.log('data: ', JSON.stringify(data, null, 2), 'ws.on message');
                if (data.event !== 'ms.channel.connect') {
                    this.LOGGER.log('if not correct event', JSON.stringify(data, null, 2), 'ws.on message');
                }
                if (data.event == "ms.channel.connect") {
                    this.emit('ready');
                    const token = data?.data?.token;
                    if (token) {
                        const sToken = String(token);
                        this.LOGGER.log('got token', sToken, 'getToken');
                        this.TOKEN = sToken;
                        this.WS_URL = this._getWSUrl();
                        if (this.SAVE_TOKEN) {
                            this._saveTokenToFile(sToken);
                        }
                        connection.close();
                    }
                }
            });
            connection.on('close', () => {
                this.emit('close');
                this.LOGGER.log('', '', 'ws.on close');
                setTimeout(() => this.reconnect(), 1000);
            });
            connection.on('error', (err) => {
                let errorMsg = '';
                if (err.message === 'EHOSTUNREACH' || err.message === 'ECONNREFUSED') {
                    errorMsg = 'TV is off or unavailable';
                }
                console.error(errorMsg, err);
                this.LOGGER.error(errorMsg, err, 'ws.on error');
            });
        });
    }
    _send(command, done, eventHandle) {
        if (this.connection?.state != 'open')
            return;
        function rejected(err) {
            if (done && err)
                done(err, null);
        }
        if (done) {
            let timeout = setTimeout(() => {
                this.removeListener('data', listener);
                done(null, null);
            }, 3000);
            const listener = (d) => {
                clearTimeout(timeout);
                this.removeListener('data', listener);
                done(null, d);
            };
            this.on('data', listener);
        }
        this.LOGGER.log('sending cmd', '');
        this.connection?.send(JSON.stringify(command), rejected);
    }
    _sendPromise(command, eventHandle) {
        return new Promise((resolve, reject) => {
            this._send(command, (err, res) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(res);
                }
            }, eventHandle);
        });
    }
    _sendLegacy(key, done) {
        if (!key) {
            this.LOGGER.error('send() missing command', { key });
            return;
        }
        this.LOGGER.log('send key', key, 'sendKey');
        const connection = net.connect(this.PORT, this.IP);
        connection.setTimeout(3000);
        connection.on('connect', () => {
            const payload = this.getLegacyCommand(key);
            connection.write(payload.header);
            connection.write(payload.command);
            connection.end();
            connection.destroy();
            if (done) {
                done(null, key);
            }
        });
        connection.on('close', () => {
            this.LOGGER.log('closed connection', {}, 'connection.on close');
        });
        connection.on('error', (err) => {
            let errorMsg = '';
            if (err.code === 'EHOSTUNREACH' || err.code === 'ECONNREFUSED') {
                errorMsg = 'Device is off or unreachable';
            }
            else {
                errorMsg = err.code;
            }
            console.error(errorMsg);
            this.LOGGER.error(errorMsg, err, 'connection.on error');
            if (done) {
                done(err, key);
            }
        });
        connection.on('timeout', (err) => {
            console.error('timeout');
            this.LOGGER.error('timeout', err, 'connection.on timeout');
            if (done) {
                done(err, key);
            }
        });
    }
    _sendLegacyPromise(key) {
        return new Promise((resolve, reject) => {
            this._sendLegacy(key, (err, res) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(res);
                }
            });
        });
    }
    getLegacyCommand(key) {
        const payload = { header: '', command: '' };
        const headerData = helpers_1.chr(0x64) +
            helpers_1.chr(0x00) +
            helpers_1.chr(helpers_1.base64(this.IP).length) +
            helpers_1.chr(0x00) +
            helpers_1.base64(this.IP) +
            helpers_1.chr(helpers_1.base64(this.MAC).length) +
            helpers_1.chr(0x00) +
            helpers_1.base64(this.MAC) +
            helpers_1.chr(helpers_1.base64(this.NAME_APP).length) +
            helpers_1.chr(0x00) +
            helpers_1.base64(this.NAME_APP);
        payload.header =
            helpers_1.chr(0x00) +
                helpers_1.chr(this.APP_STRING.length) +
                helpers_1.chr(0x00) +
                this.APP_STRING +
                helpers_1.chr(headerData.length) +
                helpers_1.chr(0x00) +
                headerData;
        const commandData = helpers_1.chr(0x00) + helpers_1.chr(0x00) + helpers_1.chr(0x00) + helpers_1.chr(helpers_1.base64(key).length) + helpers_1.chr(0x00) + helpers_1.base64(key);
        payload.command =
            helpers_1.chr(0x00) +
                helpers_1.chr(this.TV_APP_STRING.length) +
                helpers_1.chr(0x00) +
                this.TV_APP_STRING +
                helpers_1.chr(commandData.length) +
                helpers_1.chr(0x00) +
                commandData;
        return payload;
    }
    _saveTokenToFile(token) {
        try {
            fs.writeFileSync(this.TOKEN_FILE, token);
            console.log('Token saved!');
        }
        catch (err) {
            console.log('File error!');
            this.LOGGER.error('catch fil esave', { err }, '_saveTokenToFile');
        }
    }
    _getTokenFromFile() {
        try {
            fs.accessSync(this.TOKEN_FILE, fs.constants.F_OK);
            console.log('File suss!');
            const fileData = fs.readFileSync(this.TOKEN_FILE);
            return fileData.toString();
        }
        catch (err) {
            console.log('File error!');
            this.LOGGER.error('if (this.SAVE_TOKEN)', { err }, 'constructor');
            return null;
        }
    }
    _getWSUrl() {
        return `${this.PORT === 8001 ? 'ws' : 'wss'}://${this.IP}:${this.PORT}/api/v2/channels/samsung.remote.control?name=${this.NAME_APP}${this.TOKEN !== '' ? `&token=${this.TOKEN}` : ''}`;
    }
}
exports.default = Samsung;
//# sourceMappingURL=samsung.js.map
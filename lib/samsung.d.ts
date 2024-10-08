/// <reference types="node" />
import { KEYS } from './keys';
import { Configuration, WSData } from './types';
import EventEmitter = require('events');
declare class Samsung extends EventEmitter {
    private IP;
    private MAC;
    private PORT;
    private APP_STRING;
    private TV_APP_STRING;
    private TOKEN;
    private NAME_APP;
    private LOGGER;
    private SAVE_TOKEN;
    private TOKEN_FILE;
    private WS_URL;
    private ws;
    private connection?;
    constructor(config: Configuration);
    getToken(done: (token: string | null) => void): void;
    getTokenPromise(): Promise<string>;
    setToken(token: string): void;
    sendKey(key: KEYS, done?: (err: Error | {
        code: string;
    } | null, res: WSData | string | null) => void): void;
    sendKeyPromise(key: KEYS): Promise<unknown>;
    sendText(text: string, done?: (err: Error | {
        code: string;
    } | null, res: WSData | string | null) => void): false | undefined;
    sendTextPromise(text: string): false | Promise<WSData | null>;
    getAppsFromTV(done?: (err: Error | {
        code: string;
    } | null, res: WSData | string | null) => void): void;
    getAppsFromTVPromise(): Promise<WSData | null>;
    getAppIcon(iconPath: string, done?: (err: Error | {
        code: string;
    } | null, res: WSData | string | null) => void): void;
    getAppIconPromise(iconPath: string): Promise<WSData | null>;
    openAppByAppIdAndType(appId: string, type: number, done?: (error: Error | {
        code: string;
    } | null, result: WSData | null) => void): void;
    openAppByAppIdAndTypePromise(appId: string, type: number): Promise<WSData | null>;
    openApp(appId: string, done?: (err: Error | {
        code: string;
    } | null, res: WSData | string | null) => void): void;
    openAppPromise(appId: string): Promise<unknown>;
    openYouTubeLink(url: string): false | Promise<unknown>;
    isAvailable(): Promise<boolean>;
    isAvailablePing(): Promise<boolean>;
    turnOn(): Promise<boolean>;
    getLogs(): void;
    closeConnection(): void;
    private reconnect;
    ready(): Promise<void>;
    private connect;
    private _send;
    private _sendPromise;
    private _sendLegacy;
    private _sendLegacyPromise;
    private getLegacyCommand;
    private _saveTokenToFile;
    private _getTokenFromFile;
    private _getWSUrl;
}
export default Samsung;

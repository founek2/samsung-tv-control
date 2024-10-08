"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMsgLaunchBrowser = exports.getMsgLaunchApp = exports.getMsgAppIcon = exports.getMsgInstalledApp = exports.getSendTextCommand = exports.getCommandByKey = exports.getVideoId = exports.base64 = exports.chr = void 0;
function chr(char) {
    return String.fromCharCode(char);
}
exports.chr = chr;
function base64(str) {
    return Buffer.from(str).toString('base64');
}
exports.base64 = base64;
function getVideoId(url) {
    const regExp = /.*(?:youtu.be\/|v\/|u\/\w\/|embed\/|watch\?v=)([^#\&\?]*).*/;
    const match = url.match(regExp);
    const videoId = match && match[1].length > 5 ? match[1] : false;
    return videoId;
}
exports.getVideoId = getVideoId;
function getCommandByKey(key) {
    return {
        method: 'ms.remote.control',
        params: {
            Cmd: 'Click',
            DataOfCmd: key,
            Option: 'false',
            TypeOfRemote: 'SendRemoteKey',
        },
    };
}
exports.getCommandByKey = getCommandByKey;
function getSendTextCommand(text) {
    return {
        method: 'ms.remote.control',
        params: {
            Cmd: base64(text),
            DataOfCmd: 'base64',
            TypeOfRemote: 'SendInputString',
        },
    };
}
exports.getSendTextCommand = getSendTextCommand;
function getMsgInstalledApp() {
    return {
        method: 'ms.channel.emit',
        params: {
            data: '',
            event: 'ed.installedApp.get',
            to: 'host',
        },
    };
}
exports.getMsgInstalledApp = getMsgInstalledApp;
function getMsgAppIcon(iconPath) {
    return {
        method: 'ms.channel.emit',
        params: {
            data: {
                iconPath,
            },
            event: 'ed.apps.icon',
            to: 'host',
        },
    };
}
exports.getMsgAppIcon = getMsgAppIcon;
function getMsgLaunchApp(app) {
    return {
        method: 'ms.channel.emit',
        params: {
            data: {
                action_type: app.app_type === 2 ? 'DEEP_LINK' : 'NATIVE_LAUNCH',
                appId: app.appId,
            },
            event: 'ed.apps.launch',
            to: 'host',
        },
    };
}
exports.getMsgLaunchApp = getMsgLaunchApp;
function getMsgLaunchBrowser() {
    return {
        "method": "ms.channel.emit",
        "params": { "event": "ed.apps.launch", "to": "host", "data": { "appId": "org.tizen.browser", "action_type": "NATIVE_LAUNCH" } }
    };
}
exports.getMsgLaunchBrowser = getMsgLaunchBrowser;
//# sourceMappingURL=helpers.js.map
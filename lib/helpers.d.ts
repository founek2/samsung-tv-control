import { App, Command } from './types';
import { KEYS } from './keys';
export declare function chr(char: number): string;
export declare function base64(str: string): string;
export declare function getVideoId(url: string): string | false;
export declare function getCommandByKey(key: KEYS): Command;
export declare function getSendTextCommand(text: any): {
    method: string;
    params: {
        Cmd: string;
        DataOfCmd: string;
        TypeOfRemote: string;
    };
};
export declare function getMsgInstalledApp(): {
    method: string;
    params: {
        data: string;
        event: string;
        to: string;
    };
};
export declare function getMsgAppIcon(iconPath: string): {
    method: string;
    params: {
        data: {
            iconPath: string;
        };
        event: string;
        to: string;
    };
};
export declare function getMsgLaunchApp(app: App): {
    method: string;
    params: {
        data: {
            action_type: string;
            appId: string;
        };
        event: string;
        to: string;
    };
};
export declare function getMsgLaunchBrowser(): {
    method: string;
    params: {
        event: string;
        to: string;
        data: {
            appId: string;
            action_type: string;
        };
    };
};

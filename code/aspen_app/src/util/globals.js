import Constants from 'expo-constants';
import * as Updates from 'expo-updates';
import { Platform } from 'react-native';

const iOSDist = Constants.manifest2?.extra?.expoClient?.ios?.buildNumber ?? Constants.manifest.ios.buildNumber;
const androidDist = Constants.manifest2?.extra?.expoClient?.android?.versionCode ?? Constants.manifest.android.versionCode;
const iOSBundle = Constants.manifest2?.extra?.expoClient?.ios?.bundleIdentifier ?? Constants.manifest.ios.bundleIdentifier;
const androidBundle = Constants.manifest2?.extra?.expoClient?.android?.package ?? Constants.manifest.android.package;
const releaseChannel = Updates.channel ?? Updates.releaseChannel;

export const GLOBALS = {
     timeoutAverage: 60000,
     timeoutSlow: 100000,
     timeoutFast: 30000,
     appVersion: Constants.manifest2?.extra?.expoClient?.version ?? Constants.manifest.version,
     appBuild: Platform.OS === 'android' ? androidDist : iOSDist,
     appSessionId: Constants.manifest2?.extra?.expoClient?.sessionid ?? Constants.sessionId,
     appPatch: Constants.manifest2?.extra?.expoClient?.extra?.patch ?? Constants.manifest.extra.patch,
     showSelectLibrary: true,
     runGreenhouse: true,
     slug: Constants.manifest2?.extra?.expoClient?.slug ?? Constants.manifest.slug,
     url: Constants.manifest2?.extra?.expoClient?.extra?.apiUrl ?? Constants.manifest.extra.apiUrl,
     releaseChannel: __DEV__ ? 'DEV' : releaseChannel,
     language: 'en',
     country: 'us',
     lastSeen: null,
     prevLaunched: false,
     pendingSearchFilters: [],
     availableFacetClusters: [],
     hasPendingChanges: false,
     solrScope: 'unknown',
     libraryId: Constants.manifest2?.extra?.expoClient?.extra?.libraryId ?? Constants.manifest.extra.libraryId,
     themeId: Constants?.manifest2?.extra?.expoClient?.extra?.themeId ?? Constants.manifest.extra.themeId,
     bundleId: Platform.OS === 'android' ? androidBundle : iOSBundle,
     greenhouse: Constants.manifest2?.extra?.expoClient?.extra?.greenhouseUrl ?? Constants.manifest.extra.greenhouseUrl,
     privacyPolicy: 'https://bywatersolutions.com/lida-app-privacy-policy'
};

export const LOGIN_DATA = {
     showSelectLibrary: true,
     runGreenhouse: true,
     num: 0,
     nearbyLocations: [],
     allLocations: [],
     extra: [],
     hasPendingChanges: false,
     loadedInitialData: false,
     themeSaved: false,
};
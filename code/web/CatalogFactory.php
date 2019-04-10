<?php

class CatalogFactory {
	/** @var array An array of connections keyed by driver name */
	private static $catalogConnections = array();

	/**
	 * @param string|null     $driver
	 * @param AccountProfile  $accountProfile
	 * @return CatalogConnection
	 */
	public static function getCatalogConnectionInstance($driver = null, $accountProfile = null){
		require_once ROOT_DIR . '/CatalogConnection.php';
		if ($driver == null){
			/** @var IndexingProfile $activeRecordProfile */
			global $activeRecordProfile;
			if ($activeRecordProfile == null || strlen($activeRecordProfile->catalogDriver) == 0){
				global $configArray;
				$driver = $configArray['Catalog']['driver'];
				if ($accountProfile == null && !empty($driver)) {
					$accountProfile = new AccountProfile();
					$accountProfile->get('driver', $driver);
					if ($accountProfile instanceof AspenError) {
						$accountProfile = null;
					}

				}
			}else{
				$driver = $activeRecordProfile->catalogDriver;

				//Load the account profile based on the indexing profile
				$accountProfile = new AccountProfile();
				$accountProfile->recordSource = $activeRecordProfile->name;
				if (!$accountProfile->find(true)){
					$accountProfile = null;
				}
			}


		}
		if (isset(CatalogFactory::$catalogConnections[$driver])){
			return CatalogFactory::$catalogConnections[$driver];
		}else{
			CatalogFactory::$catalogConnections[$driver] = new CatalogConnection($driver, $accountProfile);
			return CatalogFactory::$catalogConnections[$driver];
		}
	}
}
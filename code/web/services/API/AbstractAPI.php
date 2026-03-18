<?php

abstract class AbstractAPI extends Action{
	protected $context;
	protected $token = null;
	function __construct($context = 'external') {
		parent::__construct(false);
		$this->context = $context;
		if ($this->checkIfLiDA()) {
			$this->context = 'lida';
		}
	}

	function checkIfLiDA(): bool {
		if (function_exists('getallheaders')) {
			foreach (getallheaders() as $name => $value) {
				if ($name == 'User-Agent' || $name == 'user-agent') {
					if (str_contains($value, "Aspen LiDA")) {
						return true;
					}
				}
			}
		}
		return false;
	}

	function getLiDAVersion() {
		if (function_exists('getallheaders')) {
			foreach (getallheaders() as $name => $value) {
				if ($name == 'version' || $name == 'Version') {
					$version = explode(' ', $value);
					$version = substr($version[0], 1); // remove starting 'v'
					return floatval($version);
				}
			}
		}
		return 0;
	}

	function getLiDASession() {
		if (function_exists('getallheaders')) {
			foreach (getallheaders() as $name => $value) {
				if ($name == 'LiDA-SessionID' || $name == 'lida-sessionid') {
					$sessionId = explode(' ', $value);
					return $sessionId[0];
				}
			}
		}
		return false;
	}

	function getLiDASlug() {
		if (function_exists('getallheaders')) {
			foreach (getallheaders() as $name => $value) {
				if (strcasecmp($name, 'lida-slug') === 0) {
					return $value;
				}
			}
		}
		return false;
	}

	function getLiDAUserAgent() {
		if (function_exists('getallheaders')) {
			foreach (getallheaders() as $name => $value) {
				if ($name == 'User-Agent' || $name == 'user-agent') {
					if (str_contains($value, 'Aspen LiDA') || str_contains($value, 'aspen lida')) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * @return array
	 * @noinspection PhpUnused
	 */
	function loadUsernameAndPassword() {
		$username = $_REQUEST['username'] ?? '';
		$password = $_REQUEST['password'] ?? '';

		if (isset($_POST['username']) && isset($_POST['password'])) {
			$username = $_POST['username'];
			$password = $_POST['password'];
		}

		if (is_array($username)) {
			$username = reset($username);
		}
		if (is_array($password)) {
			$password = reset($password);
		}
		return [$username, $password];
	}

	/**
	 * @return bool|User
	 */
	function getUserForApiCall() {
		$user = false;
		[$username, $password] = $this->loadUsernameAndPassword();
		$user = UserAccount::validateAccount($username, $password);
		if ($user !== false && $user->source == 'admin') {
			//Admin users are not allowed with API calls
			return false;
		}

		//Set translations up based on the active user's desired language
		if (empty($_REQUEST['language']) && $user !== false) {
			global $activeLanguage;
			global $translator;
			$userLanguage = new Language();
			$userLanguage->code = $user->interfaceLanguage;
			if ($userLanguage->find(true)) {
				if ($userLanguage->code != $activeLanguage->code) {
					$activeLanguage = $userLanguage;
					$translator = new Translator('lang', $userLanguage->code);
				}
			}
		}

		return $user;
	}

	/**
	 * Returns valid sources for Aspen LiDA to return when making API requests for searching, browse categories, lists, etc.
	 * <ul>
	 *     <li><b>Adding new items here without proper testing can result in the app crashing and should only be updated when a source is confirmed to be working with LiDA.</b></li>
	 * </ul>
	 * @return array
	 * @noinspection PhpUnused
	 */
	public static function getValidSourcesForLiDA($context = 'browseCategory'): array {
		if ($context == 'search') {
			return [
				'event_assabet',
				'event_communico',
				'event_libcal',
				'library_calendar_event',
				'event_aspenEvent',
				'grouped_work'
			];
		} else {
			return [
				'GroupedWork',
				'List',
				'Events'
			];
		}
	}

	/**
	 * Extracts the Bearer token from the Authorization header
	 * @return string|null
	 */
	protected function getBearerToken(): ?string {
		$headers = getallheaders();
		if (!isset($headers['Authorization'])) {
			return null;
		}
		if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
			return $matches[1];
		}
		return null;
	}

	/**
	 * Validates a JWT token
	 * @param $token
	 * @param array $requiredScopes
	 * @return bool
	 */
	protected function validateToken($token, array $requiredScopes = []): bool {
		if (!APIAuthKeySetting::verifyToken($token)) {
			return false;
		}

		$parts = explode('.', $token);
		if (count($parts) != 3) {
			return false;
		}
		list($headerB64, $bodyB64, $signatureB64) = $parts;

		$header = json_decode(base64_decode(strtr($headerB64, '-_', '+/')), true);
		$payload = json_decode(base64_decode(strtr($bodyB64, '-_', '+/')), true);
		$signature = base64_decode(strtr($signatureB64, '-_', '+/'));

		if (!$header || $header['alg'] !== 'HS256') {
			return false;
		}

		$dataToSign = $headerB64 . $bodyB64;


		$expectedSignature = hash_hmac('sha256', $dataToSign, SystemVariables::getJwtKey(), true);

		if (!hash_equals($signature, $expectedSignature)) {
			return false;
		}

		if (isset($payload['exp']) && $payload['exp'] < time()) {
			return false;
		}

		if (!empty($requiredScopes)) {
			if (!isset($payload['scope'])) {
				return false;
			}

			$tokenScopes = is_string($payload['scope']) ? explode(',', $payload['scope']) : $payload['scope'];
			$tokenScopes = array_map('trim', $tokenScopes); // Remove any whitespace

			foreach ($requiredScopes as $scope) {
				if (!in_array($scope, $tokenScopes)) {
					return false;
				}
			}
		}

		$this->token = $token;
		return true;
	}

	/**
	 * Check if the request is properly authenticated via JWT and required scopes
	 * @param array $requiredScopes
	 * @return bool
	 */
	protected function tryJWTAuth(array $requiredScopes = []): bool {
		$token = $this->getBearerToken();
		if ($token && $this->validateToken($token, $requiredScopes)) {
			return true;
		}
		return false;
	}

	/**
	 * Check if the current request is authenticated via JWT
	 * @return bool
	 */
	protected function isJWTAuthenticated(): bool {
		$token = $this->getBearerToken();
		return $token !== null && $this->validateToken($token);
	}

	/**
	 * Verify JWT has required write permissions for the given scope
	 * @param string $writeScope The write scope to check (e.g., 'api:list:write')
	 * @return array|null Returns error array if unauthorized, null if authorized
	 */
	protected function verifyJWTWriteAccess(string $writeScope): ?array {
		if ($this->isJWTAuthenticated()) {
			if (!$this->tryJWTAuth([$writeScope])) {
				return [
					'success' => false,
					'message' => 'Insufficient permissions. Write access required for this operation.',
				];
			}
		}
		return null; // No JWT auth or authorized
	}

	/**
	 * Get list of write methods for this API
	 * @return array
	 */
	protected function getWriteMethods(): array {
		return [];
	}

	/**
	 * Get the appropriate JWT scope for write operations
	 * @return string
	 */
	protected function getWriteScope(): string {
		return 'api:write';
	}

	/**
	 * Get the appropriate JWT scope for read operations
	 * @return string
	 */
	protected function getReadScope(): string {
		return 'api:read';
	}

	/**
	 * Get list of read methods for this API
	 * @return array
	 */
	protected function getReadMethods(): array {
		return [];
	}

	/**
	 * Get list of methods that do not require authentication for this API
	 * @return array
	 */
	protected function getOpenMethods(): array {
		return [];
	}
}
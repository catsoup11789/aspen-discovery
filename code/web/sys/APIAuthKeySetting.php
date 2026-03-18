<?php /** @noinspection PhpMissingFieldTypeInspection */

class APIAuthKeySetting extends DataObject {
	public $__table = 'api_auth_key';
	public $id;
	public $token;
	public $scopes;
	public $description;
	public $expiresAt;
	public $createdAt;
	public $userId;

	static $_objectStructure = [];

	static function getObjectStructure(string $context = ''): array {
		if (isset(self::$_objectStructure[$context]) && self::$_objectStructure[$context] !== null) {
			return self::$_objectStructure[$context];
		}

		$scopesOptions = self::getScopeOptions();

		$structure = [
			'id' => [
				'property' => 'id',
				'type' => 'label',
				'label' => 'Id',
			],
			'description' => [
				'property' => 'description',
				'type' => 'text',
				'label' => 'Name',
				'maxLength' => 50,
				'required' => true,
				'readOnly' => ($context !== 'addNew'),
				'note' => 'Names cannot be modified after token creation.',
			],
			'token' => [
				'property' => 'token',
				'type' => 'label',
				'label' => 'Token',
				'note' => 'Auto generated token upon saving. This is the value that should be used in the Authorization header as a Bearer token when making API requests.',
				'readonly' => false,
				'hideInLists' => true,
			],
			'scopes' => [
				'property' => 'scopes',
				'type' => 'multiSelect',
				'listStyle' => 'checkboxSimple',
				'values' => $scopesOptions,
				'label' => 'API Scopes',
				'description' => 'Select what APIs this token should have access to and read/write permissions',
				'required' => true,
				'hideInLists' => true,
				'readOnly' => ($context !== 'addNew'),
				'note' => 'Scopes cannot be modified after token creation.',
				'onchange' => 'AspenDiscovery.Admin.handleAPIScopeDependencies(this)',
			],
			'expiresAt' => [
				'property' => 'expiresAt',
				'type' => 'date',
				'label' => 'Expires At',
				'required' => true,
			],
			'createdAt' => [
				'property' => 'createdAt',
				'type' => 'label',
				'label' => 'Created At',
				'default' => Date('Y-m-d H:i:s'),
				'readOnly' => false,
			],
			'userId' => [
				'property' => 'userId',
				'type' => 'label',
				'label' => 'Created by User',
				'default' => UserAccount::getActiveUserId(),
				'hideInLists' => true,
			],
		];

		if ($context == 'addNew') {
			unset($structure['createdAt']);
			unset($structure['userId']);
			unset($structure['token']);
		}

		self::$_objectStructure[$context] = $structure;
		return self::$_objectStructure[$context];
	}

	static function getScopeOptions(): array {
		return [
			'api:work:read' => 'Work API Read Access',
			'api:user:read' => 'User API Read Access',
			'api:user:write' => 'User API Write Access',
			'api:list:read' => 'List API Read Access',
			'api:list:write' => 'List API Write Access',
			'api:item:read' => 'Item API Read Access',
			'api:event:read' => 'Event API Read Access',
			'api:event:write' => 'Event API Write Access',
			'api:search:read' => 'Search API Read Access',
			'api:system:read' => 'System API Read Access',
			'api:fine' => 'Fine API Read Access',
			'api:community:read' => 'Community API Read Access',
			'api:community:write' => 'Community API Write Access',
		];
	}

	public function fetch(): bool|DataObject|null {
		$result = parent::fetch();
		if ($result && !empty($this->scopes)) {
			if (is_string($this->scopes)) {
				$scopesArray = explode(',', $this->scopes);
				$validScopes = self::getScopeOptions();
				$selectedScopes = [];
				foreach ($validScopes as $scopeKey => $scopeLabel) {
					if (in_array($scopeKey, $scopesArray)) {
						$selectedScopes[$scopeKey] = $scopeLabel;
					}
				}
				$this->scopes = $selectedScopes;
			}
		}
		return $result;
	}

	public function insert(string $context = ''): int|bool {
		if (empty($this->createdAt)) {
			$this->createdAt = date('Y-m-d H:i:s');
		}
		if (empty($this->userId)) {
			$this->userId = UserAccount::getActiveUserId();
		}

		$this->processScopes();

		if (empty($this->token)) {
			$this->token = '';
		}

		$ret = parent::insert();
		if ($ret !== FALSE) {
			$this->createTokenOnInsert();
			parent::update();
		}

		return $ret;
	}

	public function update(string $context = ''): int|bool {
		$this->processScopes();
		return parent::update();
	}


	public function processScopes(): void {
		if (is_array($this->scopes)) {
			$this->scopes = implode(',', $this->scopes);
		}
	}

	public function createTokenOnInsert(): void {
		global $library;
		if (!SystemVariables::getJwtKey()) {
			AspenError::raiseError('JWT key not set in System Variables. Cannot create token.');
		}

		if (!isset($this->scopes)) {
			AspenError::raiseError('Scopes for this token must be set.');
		}

		$header = [
			'typ' => 'JWT',
			'alg' => 'HS256'
		];

		$claims = [
			'iss' => $library->displayName . '_' . $this->userId,
			'jti' => $this->id,
			'sub' => $this->userId,
			'aud' => $this->description,
			'exp' => strtotime($this->expiresAt),
			'iat' => strtotime($this->createdAt),
			'scope' => $this->scopes
		];

		$base64Encode = function ($data) {
			return rtrim(strtr(base64_encode(json_encode($data)), '+/', '-_'), '=');
		};
		$headerEncoded = $base64Encode($header);
		$payloadEncoded = $base64Encode($claims);

		$signature = hash_hmac('sha256', $headerEncoded . $payloadEncoded, SystemVariables::getJwtKey(), true);
		$signatureEncoded = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');

		$this->__set('token', $headerEncoded . "." . $payloadEncoded . "." . $signatureEncoded);
	}


}
<?php

require_once ROOT_DIR . '/Action.php';
require_once ROOT_DIR . '/services/Admin/ObjectEditor.php';
require_once ROOT_DIR . '/sys/APIAuthKeySetting.php';

class Admin_APIAccessTokens extends ObjectEditor {
	function getObjectType(): string {
		return 'APIAuthKeySetting';
	}

	function getToolName(): string {
		return 'APIAccessTokens';
	}

	function getPageTitle(): string {
		return 'API Access Tokens';
	}

	function getAllObjects(int $page, int $recordsPerPage): array {
		$list = [];

		$object = new APIAuthKeySetting();
		$object->orderBy($this->getSort());
		$this->applyFilters($object);
		$object->limit(($page - 1) * $recordsPerPage, $recordsPerPage);
		$object->find();
		while ($object->fetch()) {
			$list[$object->id] = clone $object;
		}

		return $list;
	}

	function getDefaultSort(): string {
		return 'description asc';
	}

	function getObjectStructure($context = ''): array {
		return APIAuthKeySetting::getObjectStructure($context);
	}

	function getPrimaryKeyColumn(): string {
		return 'id';
	}

	function getIdKeyColumn(): string {
		return 'id';
	}

	function getBreadcrumbs(): array {
		$breadcrumbs = [];
		$breadcrumbs[] = new Breadcrumb('/Admin/Home', 'Administration Home');
		$breadcrumbs[] = new Breadcrumb('/Admin/Home#primary_configuration', 'Primary Configuration');
		$breadcrumbs[] = new Breadcrumb('/Admin/APIAccessTokens', 'API Access Tokens');
		return $breadcrumbs;
	}

	function getInstructions(): string {
		return ''; // tbd
	}

	function getActiveAdminSection(): string {
		return 'primary_configuration';
	}

	public function getViewPermissions(): array {
		return ['Administer API Access Tokens'];
	}

}
<?php
/** @noinspection SqlDialectInspection */

/** @noinspection PhpUnused */
function getUpdates26_04_00(): array {
	$now = time();

	return [
		/*'name' => [
			 'title' => '',
			 'description' => '',
			 'continueOnError' => false,
			 'sql' => [
				 ''
			 ]
		 ], //name*/

		//mark n

		//kirstien
		'add_jwt_tokens' => [
			'title' => 'Add JWT Tokens',
			'description' => 'Add JWT Tokens',
			'continueOnError' => false,
			'sql' => [
				"CREATE TABLE IF NOT EXISTS `api_auth_key` (
					  `id` int(11) NOT NULL AUTO_INCREMENT,
					  `token` varchar(512) NOT NULL,
					  `scopes` text NOT NULL,
					  `description` text,
					  `expiresAt` datetime,
					  `createdAt` datetime,
					  `userId` int(11),
					  `lastUsedAt` datetime,
					  `numCalls` int(11) NOT NULL DEFAULT 0,
					  PRIMARY KEY (`id`),
					  UNIQUE KEY `token` (`token`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"
			],
		],
		//add_jwt_tokens
		'add_jwt_key_to_system_variables' => [
			'title' => 'Add JWT Key to System Variables',
			'description' => 'Add JWT Key to System Variables',
			'continueOnError' => false,
			'sql' => [
				"ALTER TABLE system_variables ADD COLUMN jwtKey varchar(512) NOT NULL DEFAULT ''",
			]
		],
		//add_jwt_key_to_system_variables
		'add_jwt_token_permissions' => [
			'title' => 'Add JWT Token Permissions',
			'description' => 'Add JWT Token Permissions',
			'continueOnError' => false,
			'sql' => [
				"INSERT INTO permissions (sectionName, name, requiredModule, weight, description) VALUES
				('Primary Configuration', 'Administer API Access Tokens', '', 160, 'Allows the user to manage JWT tokens for API access.')"
			],
		],
		//add_jwt_token_permissions
		'set_jwt_token_permission_roles' => [
			'title' => 'JWT Token Role Permission',
			'description' => 'Assign JWT Token permission to OPAC Admin role.',
			'continueOnError' => false,
			'sql' => [
				"INSERT INTO role_permissions(roleId, permissionId) VALUES ((SELECT roleId from roles where name='opacAdmin'), (SELECT id from permissions where name='Administer API Access Tokens'))",
			],
		],
		//set_jwt_token_permission_roles


		//kodi

		//yanjun

		//imani

		//galen

		//chloe

		//mark j

		//lucas

		//tomas

		// stephen

		//other


	];
}

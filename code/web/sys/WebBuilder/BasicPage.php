<?php


class BasicPage extends DataObject
{
	public $__table = 'web_builder_basic_page';
	public $id;
	public $title;
	public $urlAlias;
	public $showSidebar;
	public $contents;

	static function getObjectStructure()
	{
		$structure = [
			'id' => array('property' => 'id', 'type' => 'label', 'label' => 'Id', 'description' => 'The unique id within the database'),
			'title' => array('property' => 'title', 'type' => 'text', 'label' => 'Title', 'description' => 'The title of the page', 'size' => '40', 'maxLength'=>100),
			'urlAlias' => array('property' => 'urlAlias', 'type' => 'text', 'label' => 'URL Alias (no domain)', 'description' => 'The url of the page (no domain name)', 'size' => '40', 'maxLength'=>100),
			'showSidebar' => array('property' => 'showSidebar', 'type' => 'checkbox', 'label' => 'Show Sidebar', 'description' => 'Whether or not the sidebar should be shown'),
			'contents' => array('property' => 'contents', 'type' => 'html', 'label' => 'Page Contents', 'description' => 'The contents of the page'),
		];
		return $structure;
	}
}
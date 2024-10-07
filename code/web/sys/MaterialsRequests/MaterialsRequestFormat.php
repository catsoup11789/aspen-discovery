<?php /** @noinspection PhpMissingFieldTypeInspection */

require_once ROOT_DIR . '/sys/DB/DataObject.php';

class MaterialsRequestFormat extends DataObject {
	public $__table = 'materials_request_formats';
	public $id;
	public $libraryId;
	public $format;
	public $formatLabel;
	public $authorLabel;
	public $specialFields;   // SET Data type, possible values: 'Abridged/Unabridged', 'Article Field', 'Eaudio format', 'Ebook format', 'Season'
	public $activeForNewRequests;
	public $weight;

	static $materialsRequestFormatsSpecialFieldOptions = [
		'Abridged/Unabridged',
		'Article Field',
		'Eaudio format',
		'Ebook format',
		'Season',
	];


	/** @noinspection PhpUnusedParameterInspection */
	static function getObjectStructure($context = ''): array {
		return [
			'id' => [
				'property' => 'id',
				'type' => 'label',
				'label' => 'Id',
				'description' => 'The unique id',
			],
			'weight' => [
				'property' => 'weight',
				'type' => 'integer',
				'label' => 'Weight',
				'description' => 'The sort order',
				'default' => 0,
			],
			'format' => [
				'property' => 'format',
				'type' => 'text',
				'label' => 'Format',
				'description' => 'internal value for format, please use camelCase and no spaces ie. cdAudio',
			],
			'formatLabel' => [
				'property' => 'formatLabel',
				'type' => 'text',
				'label' => 'Format Label',
				'description' => 'Label for the format that will be displayed to users.',
			],
			'authorLabel' => [
				'property' => 'authorLabel',
				'type' => 'text',
				'label' => 'Author Label',
				'description' => 'Label for the author field associated with this format that will be displayed to users.',
			],
			'specialFields' => [
				'property' => 'specialFields',
				'type' => 'multiSelect',
				'listStyle' => 'checkboxList',
				'label' => 'Special Fields for Format',
				'description' => 'Any Special Fields to use with this format',
				'values' => self::$materialsRequestFormatsSpecialFieldOptions,
			],
			'activeForNewRequests' => [
				'property' => 'activeForNewRequests',
				'type' => 'checkbox',
				'label' => 'Active for new requests?',
				'description' => 'Whether or not the format should be active for patrons.',
				'default' => 1,
			],
		];
	}

	static function getDefaultMaterialRequestFormats($libraryId = -1) : array {
		$defaultFormats = [];

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'book';
		$defaultFormat->formatLabel = 'Book';
		$defaultFormat->authorLabel = 'Author';
		$defaultFormat->specialFields = []; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'largePrint';
		$defaultFormat->formatLabel = 'Large Print';
		$defaultFormat->authorLabel = 'Author';
		$defaultFormat->specialFields = []; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'dvd';
		$defaultFormat->formatLabel = 'DVD';
		$defaultFormat->authorLabel = 'Actor / Director';
		$defaultFormat->specialFields = ['Season']; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		/** @noinspection SpellCheckingInspection */
		$defaultFormat->format = 'bluray';
		$defaultFormat->formatLabel = 'Blu-ray';
		$defaultFormat->authorLabel = 'Actor / Director';
		$defaultFormat->specialFields = ['Season']; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'cdAudio';
		$defaultFormat->formatLabel = 'CD Audio Book';
		$defaultFormat->authorLabel = 'Author';
		$defaultFormat->specialFields = ['Abridged/Unabridged']; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'cdMusic';
		$defaultFormat->formatLabel = 'Music CD';
		$defaultFormat->authorLabel = 'Artist / Composer';
		$defaultFormat->specialFields = []; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'ebook';
		$defaultFormat->formatLabel = 'eBook';
		$defaultFormat->authorLabel = 'Author';
		$defaultFormat->specialFields = ['Ebook format']; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'eaudio';
		$defaultFormat->formatLabel = 'eAudio';
		$defaultFormat->authorLabel = 'Author';
		$defaultFormat->specialFields = [
			'Eaudio format',
			'Abridged/Unabridged',
		]; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'playaway';
		$defaultFormat->formatLabel = 'Playaway';
		$defaultFormat->authorLabel = 'Author';
		$defaultFormat->specialFields = ['Abridged/Unabridged']; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'article';
		$defaultFormat->formatLabel = 'Article';
		$defaultFormat->authorLabel = 'Author';
		$defaultFormat->specialFields = ['Article Field']; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'cassette';
		$defaultFormat->formatLabel = 'Cassette';
		$defaultFormat->authorLabel = 'Artist / Composer';
		$defaultFormat->specialFields = ['Abridged/Unabridged']; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'vhs';
		$defaultFormat->formatLabel = 'VHS';
		$defaultFormat->authorLabel = 'Actor / Director';
		$defaultFormat->specialFields = ['Season']; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		$defaultFormat = new MaterialsRequestFormat();
		$defaultFormat->libraryId = $libraryId;
		$defaultFormat->format = 'other';
		$defaultFormat->formatLabel = 'Other';
		$defaultFormat->authorLabel = 'Author';
		$defaultFormat->specialFields = []; // (Abridged/Unabridged, Article Field, Eaudio format, Ebook format, Season)
		$defaultFormat->weight = count($defaultFormats) + 1;
		$defaultFormats[] = $defaultFormat;

		return $defaultFormats;
	}


	static function getAuthorLabelsAndSpecialFields($libraryId) : array {
		// Format Labels
		$formats = new MaterialsRequestFormat();
		$formats->libraryId = $libraryId;
		$usingDefaultFormats = $formats->count() == 0;

		// Get Author Labels for all Formats
		$specialFieldFormats = [];
		$formatAuthorLabels = [];
		if ($usingDefaultFormats) {
			$defaultFormats = self::getDefaultMaterialRequestFormats();
			/** @var MaterialsRequestFormat $format */
			foreach ($defaultFormats as $format) {
				// Gather default Author Labels and default special Fields
				$formatAuthorLabels[$format->format] = translate([
					'text' => $format->authorLabel,
					'isPublicFacing' => true,
				]);
				if (!empty($format->specialFields)) {
					$specialFieldFormats[$format->format] = $format->specialFields;
				}
			}

		} else {
			$formats->find();
			while ($formats->fetch()) {
				$formatAuthorLabels[$formats->format] = translate([
					'text' => $formats->authorLabel,
					'isPublicFacing' => true,
				]);
			}

			// Get Formats that use Special Fields
			$formats = new MaterialsRequestFormat();
			$formats->libraryId = $libraryId;
			$formats->whereAdd('specialFields IS NOT NULL');
			$formats->find();
			while ($formats->fetch()) {
				$specialFieldFormats[$formats->format] = $formats->specialFields;
			}
		}

		return [
			$formatAuthorLabels,
			$specialFieldFormats,
		];
	}

	public function fetch(): bool|DataObject|null {
		$return = parent::fetch();
		if ($return) {
			$this->specialFields = empty($this->specialFields) ? null : explode(',', $this->specialFields);
		}
		return $return;
	}

	/** @noinspection PhpMissingReturnTypeInspection */
	public function insert($context = '') {
		if (is_array($this->specialFields)) {
			$this->specialFields = implode(',', $this->specialFields);
		} else {
			$this->specialFields = '';
		}
		return parent::insert();
	}

	/** @noinspection PhpMissingReturnTypeInspection */
	public function update($context = '') {
		if (is_array($this->specialFields)) {
			$this->specialFields = implode(',', $this->specialFields);
		} else {
			$this->specialFields = '';
		}
		$previous = new self();
		if ($previous->get($this->id)) {
			if ($this->format != $previous->format) {
				// Format value has changed; update all related materials requests
				$materialRequest = new MaterialsRequest();
				$materialRequest->format = $previous->format;
				$materialRequest->libraryId = $this->libraryId;
				if ($materialRequest->count() > 0) {
					$materialRequest = new MaterialsRequest();
					$materialRequest->format = $previous->format;
					$materialRequest->libraryId = $this->libraryId;
					$requestsToUpdate = $materialRequest->fetchAll('id');
					foreach ($requestsToUpdate as $id) {
						$materialRequest = new MaterialsRequest();
						$materialRequest->id = $id;
						if ($materialRequest->find(true)) {
							$materialRequest->format = $this->format;
							$materialRequest->update();
						}
					}
				}
			}
			return parent::update();
		}
		return false;
	}

	function delete($useWhere = false) : int {

		$materialRequest = new MaterialsRequest();
		$materialRequest->format = $this->format;
		$materialRequest->libraryId = $this->libraryId;
		if ($materialRequest->count() == 0) {
			return parent::delete($useWhere);
		}
		return 0;

	}

	public function hasSpecialFieldOption($option) : bool {
		return is_array($this->specialFields) && in_array($option, $this->specialFields);
	}
}
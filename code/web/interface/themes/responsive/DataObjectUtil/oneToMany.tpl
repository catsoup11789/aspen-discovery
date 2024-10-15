{strip}
<div class="controls table-responsive">
	<div class="oneToManyTable">
		<table id="{$propName}" class="{if !empty($property.sortable)}sortableProperty{/if} table table-striped table-sticky" title="Values for {$property.label}">
			<thead>
			<tr>
				{if !empty($property.sortable)}
					<th>{translate text="Sort" isAdminFacing=true}</th>
				{/if}
				{foreach from=$property.structure item=subProperty}
					{if (in_array($subProperty.type, array('text', 'regularExpression', 'multilineRegularExpression', 'enum', 'date', 'checkbox', 'integer', 'textarea', 'html', 'dynamic_label')) || ($subProperty.type == 'multiSelect' && $subProperty.listStyle == 'checkboxList')) && empty($subProperty.hideInLists) }
						<th{if in_array($subProperty.type, array('text', 'regularExpression', 'multilineRegularExpression', 'enum', 'html', 'multiSelect'))} style="min-width:150px"{/if}>{translate text=$subProperty.label isAdminFacing=true}</th>
					{/if}
				{/foreach}
				{if !empty($property.canDelete) || !empty($property.editLink) || !empty($property.canEdit)}
					<th>{translate text="Actions" isAdminFacing=true}</th>
				{/if}
			</tr>
			</thead>
			<tbody>
			{foreach from=$propValue item=subObject}
				{assign var=subObjectId value=$subObject->getPrimaryKeyValue()}
				<tr id="{$propName}{$subObject->id}" class="{$propName}Row" data-id="{$subObject->id}">
					<input type="hidden" id="{$propName}Id_{$subObject->id}" name="{$propName}Id[{$subObject->id}]" value="{$subObject->id}"/>
					{if !empty($property.sortable)}
						<td>
							<span class="glyphicon glyphicon-resize-vertical"></span>
							<input type="hidden" id="{$propName}Weight_{$subObject->id}" name="{$propName}Weight[{$subObject->id}]" value="{$subObject->weight}"/>
						</td>
					{/if}
					{foreach from=$property.structure item=subProperty}
						{if in_array($subProperty.type, array('text', 'regularExpression', 'enum', 'date', 'checkbox', 'integer', 'textarea', 'html', 'dynamic_label'))  && empty($subProperty.hideInLists)}
							<td>
								{assign var=subPropName value=$subProperty.property}
								{assign var=subPropValue value=$subObject->$subPropName}
								{if $subProperty.type=='text' || $subProperty.type=='regularExpression' || $subProperty.type=='integer' || $subProperty.type=='html'}
									<input type="text" name="{$propName}_{$subPropName}[{$subObject->id}]" value="{$subPropValue|escape}" class="form-control{if $subProperty.type=="integer"} integer{/if}{if !empty($subProperty.required)} required{/if}" {if !empty($subProperty.onchange)}onchange="{$subProperty.onchange}"{/if} {if !empty($subProperty.readOnly) || !empty($property.readOnly)} readonly{/if} data-id="{$subObject->id}">
								{elseif $subProperty.type=='date'}
									<input type="date" name="{$propName}_{$subPropName}[{$subObject->id}]" value="{$subPropValue|escape}" class="form-control{if !empty($subProperty.required)} required{/if}"{if !empty($subProperty.readOnly) || !empty($property.readOnly)} readonly disabled{/if} data-id="{$subObject->id}">
								{elseif $subProperty.type=='dynamic_label'}
									<span id="{$propName}_{$subPropName}_{$subObject->id}" data-id="{$subObject->id}">{$subPropValue|escape}<span>
								{elseif $subProperty.type=='textarea' || $subProperty.type=='multilineRegularExpression'}
									<textarea name="{$propName}_{$subPropName}[{$subObject->id}]" class="form-control"{if !empty($subProperty.readOnly) || !empty($property.readOnly)} readonly{/if} data-id="{$subObject->id}">{$subPropValue|escape}</textarea>
								{elseif $subProperty.type=='checkbox'}
									{if !empty($subProperty.readOnly) || !empty($property.readOnly)}
										{if $subPropValue == 1}{translate text='Yes' isAdminFacing=true}{else}{translate text='No' isAdminFacing=true}{/if}
									{/if}
									<input type='checkbox' name='{$propName}_{$subPropName}[{$subObject->id}]' {if $subPropValue == 1}checked='checked'{/if} {if !empty($subProperty.readOnly) || !empty($property.readOnly)} style="display: none"{/if} data-id="{$subObject->id}"/>
								{else}
									{if $subObject->canActiveUserChangeSelection()}
										<select name='{$propName}_{$subPropName}[{$subObject->id}]' id='{$propName}{$subPropName}_{$subObject->id}' class='form-control {if !empty($subProperty.required)} required{/if}' {if !empty($subProperty.onchange)}onchange="{$subProperty.onchange}"{/if} {if !empty($subProperty.readOnly) || !empty($property.readOnly)} readonly disabled{/if} data-id="{$subObject->id}">
											{foreach from=$subProperty.values item=propertyName key=propertyValue}
												<option value='{$propertyValue}' {if $subPropValue == $propertyValue}selected='selected'{/if}>{if !empty($subProperty.translateValues)}{translate text=$propertyName|escape inAttribute=true isPublicFacing=$subProperty.isPublicFacing isAdminFacing=$subProperty.isAdminFacing }{else}{$propertyName|escape}{/if}</option>
											{/foreach}
										</select>
									{else}
										<input type="hidden" name='{$propName}_{$subPropName}[{$subObject->id}]' id='{$propName}{$subPropName}_{$subObject->id}' value="{$subPropValue}"/>
										{if !empty($subProperty.allValues)}
											{assign var=tmpValues value=$subProperty.allValues}
										{else}
											{assign var=tmpValues value=$subProperty.values}
										{/if}
										{foreach from=$tmpValues item=propertyName key=propertyValue}
											{if $subPropValue == $propertyValue}
												{if !empty($subProperty.translateValues)}{translate text=$propertyName inAttribute=true isPublicFacing=$subProperty.isPublicFacing isAdminFacing=$subProperty.isAdminFacing }{else}{$propertyName}{/if}
											{/if}
										{/foreach}
									{/if}
								{/if}
							</td>
						{elseif $subProperty.type == 'multiSelect'}
							{if $subProperty.listStyle == 'checkboxList'}
								<td>
									<div class="checkbox">
										{*this assumes a simple array, eg list *}
										{assign var=subPropName value=$subProperty.property}
										{assign var=subPropValue value=$subObject->$subPropName}
										{foreach from=$subProperty.values item=propertyName}
											<input name='{$propName}_{$subPropName}[{$subObject->id}][]' type="checkbox" value='{$propertyName}' {if is_array($subPropValue) && in_array($propertyName, $subPropValue)}checked='checked'{/if}{if !empty($subProperty.readOnly) || !empty($property.readOnly)} readonly disabled{/if}>
											{$propertyName|escape}
											<br>
										{/foreach}
									</div>
								</td>
							{/if}
						{/if}
					{/foreach}
					<td>
						{if $subObject->canActiveUserEdit()}
							{if !empty($property.editLink)}
						    <div class="btn-group btn-group-vertical" style="padding-top: 0">
								<a href='{$property.editLink}?objectAction=edit&widgetListId={$subObject->id}&widgetId={$widgetid}' class="btn btn-sm btn-default" title="edit">
									<i class="fas fa-pencil-alt"></i> {translate text="Edit" isAdminFacing=true}
								</a>
							{elseif !empty($property.canEdit)}
								{if method_exists($subObject, 'getEditLink')}
								<div class="btn-group btn-group-vertical" style="padding-top: 0">
									<a href='{$subObject->getEditLink($propName)}' title='Edit' class="btn btn-sm btn-default">
										<i class="fas fa-pencil-alt"></i> {translate text="Edit" isAdminFacing=true}
									</a>
								{else}
									{translate text="Please add a getEditLink method to this object" isAdminFacing=true}
								{/if}
							{/if}
						{/if}
						{* link to delete*}
						<input type="hidden" id="{$propName}Deleted_{$subObject->id}" name="{$propName}Deleted[{$subObject->id}]" value="false">
						{if !empty($property.canDelete) && $subObject->canActiveUserDelete() && empty($property.readOnly)}
							{* link to delete *}
							<a href="#" class="btn btn-sm btn-warning" onclick="if (confirm('{translate text='Are you sure you want to delete this?' inAttribute=true isAdminFacing=true}')){literal}{{/literal}$('#{$propName}Deleted_{$subObject->id}').val('true');$('#{$propName}{$subObject->id}').hide().find('.required').removeClass('required'){literal}}{/literal};return false;">
								{* On delete action, also remove class 'required' to turn off form validation of the deleted input; so that the form can be submitted by the user  *}
								<i class="fas fa-trash"></i> {translate text="Delete" isAdminFacing=true}
							</a>
                        {/if}
						{if !empty($property.editLink) || method_exists($subObject, 'getEditLink')}</div>{/if}
					</td>
				</tr>
				{foreachelse}
				<tr style="display:none">
					<td></td>
				</tr>
			{/foreach}
			</tbody>
		</table>
	</div>
	<div class="{$propName}Actions">
		{if !empty($property.canAddNew) && empty($property.readOnly)}
			<a href="#" onclick="addNew{$propName}();return false;" class="btn btn-primary btn-sm"><i class="fas fa-plus"></i> {translate text="Add New" isAdminFacing=true}</a>
		{/if}
		{if !empty($property.additionalOneToManyActions) && !empty($id)}{* Only display these actions for an existing object *}
			<div class="btn-group pull-right" style="padding-top: 0">
				{foreach from=$property.additionalOneToManyActions item=action}
					<a class="btn {if !empty($action.class)}{$action.class}{else}btn-primary{/if} btn-sm" {if !empty($action.url)}href="{$action.url|replace:'$id':$id}"{/if} {if !empty($action.onclick)}onclick="{$action.onclick|replace:'$id':$id}"{/if}>{translate text=$action.text isAdminFacing=true}</a>
				{/foreach}
			</div>
		{/if}
	</div>
	{/strip}
	<script type="text/javascript">
		{literal}$(function () {{/literal}
			{if !empty($property.sortable)}
			{literal}$('#{/literal}{$propName}{literal} tbody').sortable({
				update: function (event, ui) {
					$.each($(this).sortable('toArray'), function (index, value) {
						var inputId = '#{/literal}{$propName}Weight_' + value.substr({$propName|@strlen}); {literal}
						$(inputId).val(index + 1);
					});
				}
			});
			{/literal}
			{/if}
		{literal}});{/literal}
		var numAdditional{$propName} = 0;

		function addNew{$propName}{literal}() {
			numAdditional{/literal}{$propName}{literal} = numAdditional{/literal}{$propName}{literal} - 1;
			var newRow = "<tr>";
			{/literal}
			newRow += "<input type='hidden' id='{$propName}Id_" + numAdditional{$propName} + "' name='{$propName}Id[" + numAdditional{$propName} + "]' value='" + numAdditional{$propName} + "'>";
			{if !empty($property.sortable)}
			newRow += "<td><span class='glyphicon glyphicon-resize-vertical'></span>";
			newRow += "<input type='hidden' id='{$propName}Weight_" + numAdditional{$propName} + "' name='{$propName}Weight[" + numAdditional{$propName} + "]' value='" + (100 - numAdditional{$propName}) + "'>";
			newRow += "</td>";
			{/if}
			{foreach from=$property.structure item=subProperty}
				{if empty($subProperty.hideInLists)}
					{if in_array($subProperty.type, array('text', 'regularExpression','multilineRegularExpression', 'enum', 'date', 'checkbox', 'integer', 'textarea', 'html', 'dynamic_label')) }
						newRow += "<td>";
						{assign var=subPropName value=$subProperty.property}
						{if $subProperty.type=='text' || $subProperty.type=='regularExpression' || $subProperty.type=='multilineRegularExpression' || $subProperty.type=='integer' || $subProperty.type=='textarea'|| $subProperty.type=='html'}
							newRow += "<input type='text' name='{$propName}_{$subPropName}[" + numAdditional{$propName} + "]' value='{if !empty($subProperty.default)}{$subProperty.default}{/if}' class='form-control{if $subProperty.type=="integer"} integer{/if}{if !empty($subProperty.required)} required{/if}' data-id='" + numAdditional{$propName} + "'>";
						{elseif $subProperty.type=='date'}
							newRow += "<input type='date' name='{$propName}_{$subPropName}[" + numAdditional{$propName} + "]' value='{if !empty($subProperty.default)}{$subProperty.default}{/if}' class='form-control{if !empty($subProperty.required)} required{/if}' data-id='" + numAdditional{$propName} + "'>";
						{elseif $subProperty.type=='dynamic_label'}
							newRow += "<span id='{$propName}_{$subPropName}_" + numAdditional{$propName} + "' data-id='" + numAdditional{$propName} + "'><span>"
						{elseif $subProperty.type=='checkbox'}
							newRow += "<input type='checkbox' name='{$propName}_{$subPropName}[" + numAdditional{$propName} + "]' {if !empty($subProperty.default) && $subProperty.default == 1}checked='checked'{/if} data-id='" + numAdditional{$propName} + "'>";
						{else}
							newRow += "<select name='{$propName}_{$subPropName}[" + numAdditional{$propName} + "]' id='{$propName}{$subPropName}_" + numAdditional{$propName} + "' class='form-control{if !empty($subProperty.required)} required{/if}' {if !empty($subProperty.onchange)}onchange=\"{$subProperty.onchange}\"{/if} data-id='" + numAdditional{$propName} + "'>";
							{foreach from=$subProperty.values item=propertyName key=propertyValue}
								newRow += "<option value='{$propertyValue}' {if !empty($subProperty.default) && $subProperty.default == $propertyValue}selected='selected'{/if}>{$propertyName|escape:javascript}</option>";
							{/foreach}
							newRow += "</select>";
						{/if}
						newRow += "</td>";
					{elseif $subProperty.type == 'multiSelect'}
						{if $subProperty.listStyle == 'checkboxList'}
							newRow += '<td>';
							newRow += '<div class="checkbox">';
							{*this assumes a simple array, eg list *}
							{assign var=subPropName value=$subProperty.property}
							{foreach from=$subProperty.values item=propertyName}
								newRow += '<input name="{$propName}_{$subPropName}[' + numAdditional{$propName} + '][]" type="checkbox" value="{$propertyName}"> {$propertyName}<br>';
							{/foreach}
							newRow += '</div>';
							newRow += '</td>';
						{/if}
					{/if}
				{/if}
			{/foreach}
			newRow += "</tr>";
			{literal}
			$('#{/literal}{$propName}{literal} tr:last').after(newRow);
			return false;
		}
		{/literal}
	</script>
</div>
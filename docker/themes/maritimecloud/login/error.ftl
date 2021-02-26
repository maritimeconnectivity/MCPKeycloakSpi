<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("errorTitle")}
    <#elseif section = "form">
        <div id="kc-error-message">
            <p class="instruction">${message.summary?no_esc}</p>
            <#if client?? && client.baseUrl?has_content>
                <p><a id="backToApplication" href="${client.baseUrl}">${kcSanitize(msg("backToApplication"))?no_esc}</a></p>
            </#if>
        </div>
    </#if>
<script type="text/javascript">
    document.addEventListener("DOMContentLoaded", function () {
        var kcForm = document.getElementById("kc-form");
        var error = document.getElementById("kc-error-message");
        console.log(error);

        if (error) {
            kcForm.style.display = "inline";
        }
    });
</script>
</@layout.registrationLayout>

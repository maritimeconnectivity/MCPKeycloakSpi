<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "title">
        ${msg("errorTitle")}
    <#elseif section = "header">
        ${msg("errorTitleHtml")}
    <#elseif section = "form">
        <div id="kc-error-message">
            <p class="instruction">${message.summary}</p>
            <#if client?? && client.baseUrl?has_content>
                <p><a id="backToApplication" href="${client.baseUrl}">${msg("backToApplication")}</a></p>
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
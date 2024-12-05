timeout 600
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:disable
auditpol /set /subcategory:"Registry" /success:enable /failure:disable
auditpol /set /subcategory:"SAM" /success:enable /failure:disable
# Mantenimiento del repositorio — actualizado 2026-08-17

## Publicación y automatización

- Origen canónico privado: `https://github.com/LynxPardelle/zoolanding-data-spaces`.
- Ramas base publicadas: `main`, `test` y `dev`; promoción prevista `dev -> test -> main`.
- GitHub Actions tiene permisos de lectura por defecto. CI valida cada push y pull
  request; los despliegues sólo escuchan las ramas `test` o `main`.
- Los Environments `test` y `production` aceptan despliegues sólo desde `test`
  y `main`, respectivamente.
- Las variables de los roles OIDC/CloudFormation y del topic de alarmas están
  configuradas sin guardar credenciales AWS estáticas.
- Validación local: 109/109 pruebas, compilación, SAM, Actionlint y Gitleaks.

## Despliegue pendiente

**NO-GO para desplegar la aplicación.** Sólo se desplegaron las identidades
retenidas y acotadas; no existe el stack de Data Spaces ni sus parámetros SSM
canónicos. El topic de alarmas existe, pero no tiene suscriptores confirmados.
No se sustituyó ninguna dependencia faltante por un ARN inventado o comodín.

La protección de ramas privadas fue rechazada por el plan GitHub actual, que
exige GitHub Pro o visibilidad pública. Se mantuvo la visibilidad privada. Hasta
resolverlo, use pull requests, verifique CI y nunca fuerce historia.

No transfiera `.env`, credenciales, datos no revisados, `.aws-sam`, cachés,
entornos virtuales ni outputs. El código publicado se recupera clonando GitHub.

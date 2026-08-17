# Mantenimiento del repositorio — actualizado 2026-08-17

## Publicación y automatización

- Origen canónico público: `https://github.com/LynxPardelle/zoolanding-data-spaces`.
- Ramas base publicadas: `main`, `test` y `dev`; promoción prevista `dev -> test -> main`.
- GitHub Actions tiene permisos de lectura por defecto. CI valida cada push y pull
  request; los despliegues sólo escuchan las ramas `test` o `main`.
- Los Environments `test` y `production` aceptan despliegues sólo desde `test`
  y `main`, respectivamente.
- Roles OIDC/CloudFormation y topic de alarmas están copiados a secretos de cada
  GitHub Environment, sin credenciales AWS estáticas. Las variables duplicadas
  fueron eliminadas después de verificar correctamente la CI del commit `c3e0f46`.
- La CI ejecuta Gitleaks fijado por SHA sobre el historial completo. Los workflows
  usan sólo `secrets.*` y enmascaran el ID de cuenta AWS.
- `dev`, `test` y `main` exigen PR y CI estricto, incluyen a administradores,
  resuelven conversaciones y bloquean force-push y borrado. Secret scanning,
  push protection y actualizaciones de seguridad de Dependabot están activos.
- La proyección pública filtra campos internos también dentro de arreglos anidados
  y las lecturas de sesión/usuario son fuertemente consistentes.
- Validación local: 111/111 pruebas pasaron tres veces, compilación, SAM lint,
  Actionlint y Gitleaks correctos.

## Despliegue pendiente

**NO-GO para desplegar la aplicación.** Sólo se desplegaron las identidades
retenidas y acotadas; no existe el stack de Data Spaces ni sus parámetros SSM
canónicos. El topic de alarmas existe, pero no tiene suscriptores confirmados.
No se sustituyó ninguna dependencia faltante por un ARN inventado o comodín.

Antes de desplegar aún faltan vincular la sesión a la asignación vigente del
draft, evitar I/O de política previo a auth o añadir throttling, usar locks con
hashes, exigir aprobación independiente de promociones y comprobar un suscriptor
confirmado/canario de alarmas. Use pull requests, verifique CI y nunca fuerce
historia.

No transfiera `.env`, credenciales, datos no revisados, `.aws-sam`, cachés,
entornos virtuales ni outputs. El código publicado se recupera clonando GitHub.

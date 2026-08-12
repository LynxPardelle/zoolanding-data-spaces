# Mantenimiento pendiente — 2026-08-12

## Repositorio sin origen

Este repositorio no tiene ningún remoto Git configurado. El README lo identifica como implementación local y prohíbe desplegar o mutar AWS durante esta fase; por ello no se creó un repositorio ni se inventó un destino de publicación.

La rama local `codex/phase8-infrastructure-readiness` contiene el endurecimiento de política de esquemas y sus pruebas. El commit queda disponible sólo en esta copia hasta que se apruebe un origen.

## Decisión requerida

Antes de publicar, el propietario debe indicar:

1. la organización y el repositorio GitHub existentes que serán la fuente canónica;
2. si la visibilidad será privada o pública;
3. la rama base y el flujo de promoción compatibles con `dev -> test -> main`.

Recomendación: mantenerlo privado hasta que se aprueben el contrato entre repositorios, los responsables de mantenimiento y las puertas de despliegue. Después se debe añadir el remoto explícitamente, comparar historiales y publicar sólo si el push es fast-forward o mediante una integración revisada.

No se incluyeron secretos, identificadores operativos ni artefactos de build en el commit.

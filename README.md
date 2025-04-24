# api.template.node

# Starting redis server
sudo service redis-server start
sudo ss -tuln | grep :3000
docker ps -q | xargs -r docker kill
docker ps -q | xargs -r docker stop
sudo ss -tuln

Remove-Item -Recurse -Force node_modules, package-lock.json; npm install


{
  "email": "mabarry2018@gmail.com",
  "password": "123456PAM$45789asdssMabd58"
}

- 📦api.template.node
- ┣ 📂build
- ┃ ┗ 📂script
- ┃ ┃ ┣ 📜deploy.sh
- ┃ ┃ ┣ 📜start.sh
- ┃ ┃ ┣ 📜stop.sh
- ┃ ┃ ┗ 📜test.sh
- ┣ 📂src
- ┃ ┣ 📂api
- ┃ ┃ ┗ 📜index.ts
- ┃ ┣ 📂common
- ┃ ┃ ┣ 📂errors
- ┃ ┃ ┃ ┗ 📜httpErrors.ts
- ┃ ┃ ┣ 📂middleware
- ┃ ┃ ┃ ┣ 📜authentication.ts
- ┃ ┃ ┃ ┣ 📜errorHandler.ts
- ┃ ┃ ┃ ┣ 📜JSend.ts
- ┃ ┃ ┃ ┣ 📜queryParssing.ts
- ┃ ┃ ┃ ┗ 📜token.ts
- ┃ ┣ 📂models
- ┃ ┃ ┗ 📜Model.ts
- ┃ ┣ 📂routing
- ┃ ┃ ┣ 📜BaseRouter.ts
- ┃ ┃ ┣ 📜decorators.ts
- ┃ ┃ ┣ 📜metadata.storage.ts
- ┃ ┃ ┗ 📜register.ts
- ┃ ┣ 📂types
- ┃ ┃ ┗ 📜index.ts
- ┃ ┗ 📂utils
- ┃ ┃ ┗ 📜index.ts
- ┣ 📂config
- ┃ ┣ 📜http.ts
- ┃ ┗ 📜index.ts
- ┣ 📂database
- ┃ ┣ 📂migrations
- ┃ ┃ ┗ 📜1745082102282-$npm_config_name.ts
- ┃ ┗ 📜data-source.ts
- ┣ 📂lib
- ┃ ┣ 📂openapi-schemas
- ┃ ┃ ┣ 📜auth.schemas.ts
- ┃ ┃ ┗ 📜user.schemas.ts
- ┃ ┣ 📜logger.ts
- ┃ ┣ 📜mailer.ts
- ┃ ┣ 📜openapi.ts
- ┃ ┗ 📜redis.ts
- ┣ 📂modules
- ┃ ┣ 📂auth
- ┃ ┃ ┣ 📂models
- ┃ ┃ ┃ ┣ 📜authorization.types.ts
- ┃ ┃ ┃ ┗ 📜features.ts
- ┃ ┃ ┣ 📂services
- ┃ ┃ ┃ ┗ 📜auth.services.ts
- ┃ ┃ ┗ 📜auth.routes.ts
- ┃ ┗ 📂users
- ┃ ┃ ┣ 📂data
- ┃ ┃ ┃ ┗ 📜users.repository.ts
- ┃ ┃ ┣ 📂models
- ┃ ┃ ┃ ┗ 📜users.entity.ts
- ┃ ┃ ┣ 📂services
- ┃ ┃ ┃ ┗ 📜users.services.ts
- ┃ ┃ ┣ 📂__tests__
- ┃ ┃ ┃ ┗ 📜users.spec.ts
- ┃ ┃ ┗ 📜users.routes.ts
- ┣ 📂tests
- ┃ ┣ 📂data
- ┃ ┃ ┣ 📜1-schema.sql
- ┃ ┃ ┗ 📜2-datas.sql
- ┃ ┣ 📜docker-compose.yml
- ┃ ┗ 📜setup.ts
- ┣ 📜app.ts
- ┗ 📜server.ts
- ┣ 📜.dockerignore
- ┣ 📜.env
- ┣ 📜.env.example
- ┣ 📜.env.local
- ┣ 📜.env.test
- ┣ 📜.eslintcache
- ┣ 📜.eslintignore
- ┣ 📜.eslintrc.js
- ┣ 📜.gitignore
- ┣ 📜.prettierrc.js
- ┣ 📜Dockerfile
- ┣ 📜eslint.config.js
- ┣ 📜package.json
- ┣ 📜README.md
- ┣ 📜tsconfig.json
- ┗ 📜vitest.config.ts

# Fastapi authentication

| Property               |       Value       |
|:-----------------------|:-----------------:|
| Authentication type    |  Form based auth  |
| Credentials            | email & password  |
| Access-token type      |        JWT        | 
| Access-token placed in |      COOKIE       | 


<h4><i>
For authentication uses form, where user input username and password. <br>
If input data is valid, will be created jwt-token and placed it in COOKIES.
</i></h4>

---

#### The project has implemented:
* Super_admin can add to database users with different roles.
* Users can pass authentication with email and password placed in form.
* A JWT-token is generated during the authentication process and placed in COOKIES.
* Authenticated user can access endpoints via GET methods
* Authenticated admins can access endpoints via GET, POST, PUT, DELETE methods
* Logout process implemented by deleting access-token from cookie.

---

### Prepare virtual enviroinment
><h4>The project uses poetry to install dependencies.</h4>
>
>* To install dependencies in project dir run shell-command:
>
>```
>POETRY_VIRTUALENVS_IN_PROJECT=true poetry shell
>```
>
>* then run next command:
>
>```
>poetry install
>```

### Prepare database

>The postgres database is used for data storage
>
>* For launch postgres database in docker container run command:
>
>```
>docker compose up -d
>```


### Prepare environments
>##### Needed environments are placed in *.env* file
>
>* You must create and fill in the **.env** file by analogy with the **.env.template** file

### Run project
>##### You can run project with shell-command:
>
>```bash
>python src/loader.py
>```

### Logging as super_admin
>##### You can log as admin with follow credentials:
>* username = admin@example.com
>* password = 1234567890

### Tests
><p> The tests are implemented with pytest. <br>
> To be able to run tests you should have database with name "pytest_db".
></p>


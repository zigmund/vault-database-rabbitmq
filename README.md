# vault-database-rabbitmq

Custom [Hashicorp Vault](https://developer.hashicorp.com/vault) database plugin for RabbitMQ.

See also:
- [Database secrets engine](https://developer.hashicorp.com/vault/docs/secrets/databases)
- [Custom database secrets engines](https://developer.hashicorp.com/vault/docs/secrets/databases/custom)

## Prerequisites

This database plugin utilizes RabbitMQ http api for user management, so [RabbitMQ Management Plugin](https://www.rabbitmq.com/docs/management) should be installed and activated.

## Register plugin in vault

1. Create directory for vault plugins and set `plugin_directory` param in vault server config. Repeat for all nodes in cluster.
2. Copy plugin binary to plugins directory. Repeat for all nodes in cluster.
3. Take sha256 of plugin binary: `sha256sum vault-plugin-database-rabbitmq`
4. Register plugin in vault:
    ```bash
    zigmund@bug ~ % vault write sys/plugins/catalog/database/rabbitmq-database-plugin \
      sha256="<SHA256 sum of plugin binary>" \
      command="vault-plugin-database-rabbitmq"`
    ```
5. Verify plugin state:
    ```bash
    zigmund@bug ~ % vault plugin list database
    Name                                 Version
    ----                                 -------
    cassandra-database-plugin            v1.14.4+builtin.vault
    couchbase-database-plugin            v0.9.2+builtin
    elasticsearch-database-plugin        v0.13.2+builtin
    hana-database-plugin                 v1.14.4+builtin.vault
    influxdb-database-plugin             v1.14.4+builtin.vault
    mongodb-database-plugin              v1.14.4+builtin.vault
    mongodbatlas-database-plugin         v0.10.0+builtin
    mssql-database-plugin                v1.14.4+builtin.vault
    mysql-aurora-database-plugin         v1.14.4+builtin.vault
    mysql-database-plugin                v1.14.4+builtin.vault
    mysql-legacy-database-plugin         v1.14.4+builtin.vault
    mysql-rds-database-plugin            v1.14.4+builtin.vault
    postgresql-database-plugin           v1.14.4+builtin.vault
    rabbitmq-database-plugin             v0.0.1-alpha          <
    redis-database-plugin                v0.2.1+builtin
    redis-elasticache-database-plugin    v0.2.1+builtin
    redshift-database-plugin             v1.14.4+builtin.vault
    snowflake-database-plugin            v0.9.0+builtin
    ```
   If the plugin not in list or the version is displayed as `n/a` - check vault debug logs of retry procedure with `vault monitor -log-level=debug`.

## Usage

The plugin can be used as any other builtin database plugin. See also: [Database secrets engine](https://developer.hashicorp.com/vault/docs/secrets/databases)

1. Create user with administrative permissions in RabbitMQ.
2. Enable the database secrets engine in Vault:
    ```bash
    zigmund@bug ~ % vault secrets enable database
    Success! Enabled the database secrets engine at: database/
    ```
3. Create database connection of type `rabbitmq-database-plugin`:
    ```
    zigmund@bug ~ % vault write database/config/my-rabbitmq \
        plugin_name=rabbitmq-database-plugin \
        allowed_roles="my-role" \
        connection_url="http://rabbitmq-host:15672"
        username="vault" \
        password="vault-password" \
        insecure_skip_verify=true \
        timeout=15s
    ```
    
    `insecure_skip_verify` - optional param in case of using self-signed certs in RabbitMQ TLS endpoint.
    `timeout` - optional param to override default 5s timeout. 
4. Create role with user tags and permissions in creation statements:
    ```bash
    zigmund@bug ~ % vault write database/roles/my-role
      db_name=my-db \
      default_ttl="1h" \
      max_ttl="24h" \
      creation_statements='{"tags":["administrator"],"permissions":[{"vhost":"/vhost","read":".*","write":".*","configure":".*"}]}'
    ```
    `creation_statements` - json-encoded access params for the role.
    JSON schema:
    ```
    {
      "tags": []string - array of user tags
      "permissions": []struct - array of permissions: 
        {
          "vhost": string - vhost,
          "read": string - regex for read access
          "write": string - regex for write access
          "configure": string - regex for configure access
        }
    }
    ```
    See also: [Authentication, Authorisation, Access Control](https://www.rabbitmq.com/docs/access-control)
5. Now you can use generate credentials:
    ```bash
    zigmund@bug ~ % vault read database/creds/my-role
    Key                Value
    ---                -----
    lease_id           database/creds/my-role/c5UcJL99ppVp0JkVqzhjxTeq
    lease_duration     1h
    lease_renewable    true
    password           YX-3XDMYbncyosQTrj28
    username           v-root-my-role-7gbL0TwnD2ksoQGglPS4-1750415140
    ```

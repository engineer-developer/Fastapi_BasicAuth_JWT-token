FROM postgres:16.4

ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres

COPY *.conf /etc/postgres/

CMD ["postgres", "-c", "config_file=/etc/postgres/postgresql.conf", \
                 "-c", "hba_file=/etc/postgres/pg_hba.conf"]

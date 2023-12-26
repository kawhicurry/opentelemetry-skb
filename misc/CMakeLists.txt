

set(SHELL sh)

file(COPY docker-compose DESTINATION .)

add_custom_command(OUTPUT compose-up
    POST_BUILD
    COMMAND ${SHELL} -c 'cd docker-compose && docker-compose up -d'
    # COMMAND ${SHELL} -c 'ls -al && pwd'
)

add_custom_command(OUTPUT compose-down
    POST_BUILD
    COMMAND ${SHELL} -c 'cd docker-compose && docker-compose down'
    # COMMAND ${SHELL} -c 'ls -al && pwd'
)

add_custom_target(docker-compose-up
    DEPENDS compose-up
)

add_custom_target(docker-compose-down
    DEPENDS compose-down
)
add_executable(zrtpRecv zrtpRecv.c)
target_link_libraries(zrtpRecv ${LIBS})

add_executable(zrtpRecvMulti zrtpRecvMulti.c)
target_link_libraries(zrtpRecvMulti ${LIBS})

add_executable(zrtpSend zrtpSend.c)
target_link_libraries(zrtpSend ${LIBS})


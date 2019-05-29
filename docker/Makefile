VERSION=0.2
SHARE=share
NAME=memsight

all:	build-share run
	

build-share:
	mkdir -p ${SHARE}

run:
	sudo docker run --rm -ti --name=${NAME} -v `pwd`/${SHARE}:/home/ubuntu/share -h ubuntu ${NAME}-${VERSION}

clean:
	sudo docker rm ${NAME}-${VERSION}

build:
	#-sudo docker rmi ${NAME}-${VERSION}
	sudo docker build -t ${NAME}-${VERSION} -f Dockerfile ../..

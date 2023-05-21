from utils.docker_image_scan import DockerImageScanResponse, DockerImageScan
from datetime import datetime


class DockerImageScanner:
    """The main class for scanning docker image tar file"""

    def __init__(self) -> None:
        self.__docker_image_scan = DockerImageScan()

    def start_app(self):
        scan_response = self.__docker_image_scan.start_scan()
        self.__post_scan(scan_response)

    def __post_scan(self, scan_response: DockerImageScanResponse):

        print(str(datetime.now()) + " - Docker Image Report:")
        print(("{}{}".format('verdict: '.ljust(20), scan_response.verdict)))
        if scan_response.verdict == "VULNERABLE":
            for indication, source, layer in zip(scan_response.indications, scan_response.sources, scan_response.layers):
                print("-----------------------------------------------------------------------------------------------")
                print(("{}{}".format('indication: '.ljust(20), indication)))
                print(("{}{}".format('source: '.ljust(20), source)))
                print(("{}".format('layer metadata: '.ljust(20))))
                print(("{}{}{}".format(' '.ljust(20), 'id: '.ljust(20), layer.layer_id)))
                print(("{}{}{}".format(' '.ljust(20), 'parent: '.ljust(20), layer.parent)))
                print(("{}{}{}".format(' '.ljust(20), 'created: '.ljust(20), layer.created)))
                print(("{}{}{}".format(' '.ljust(20), 'container: '.ljust(20), layer.container)))
                print(("{}{}{}".format(' '.ljust(20), 'container_config: '.ljust(20), layer.container_config)))
        if scan_response.error:
            print(("{}{}".format('error: '.ljust(20), scan_response.error)))


def main():
    scanner = DockerImageScanner()
    scanner.start_app()


if __name__ == '__main__':
    main()

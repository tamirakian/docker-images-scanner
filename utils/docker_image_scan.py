import json
import os
import time
from pathlib import Path
import tarfile
from dataclasses import dataclass
from datetime import datetime

from engines.hard_coded_credentials_engine import HardCodedCredentialsEngine
from utils.docker_image_layer_metadata import DockerImageLayerMetadata

_EXTRACTED_IMAGE_PATH = ".\\extraction_dir"
_IMAGE_ROOT = "image root"


@dataclass
class DockerImageScanResponse:
    """A class for storing the scan response's report"""
    verdict: str
    indications: list = None
    sources: list = None
    layers: list = None
    error: str = None


class DockerImageScan:
    """A class for handling the scan process"""

    def __init__(self):
        self.__hard_coded_cred_engine = HardCodedCredentialsEngine()
        self.__indications_list = []
        self.__sources_list = []
        self.__verdict = "BENIGN"
        self.__layer_metadata = []
        self.__image_file_name = ""

    def start_scan(self):
        file_path = input("\n\nPlease enter the Docker image file path:")
        while not file_path.endswith(".tar"):
            file_path = input("Please enter a valid TAR file path:")

        image_file_base_path = os.path.basename(file_path)
        self.__image_file_name = os.path.splitext(image_file_base_path)[0]

        try:
            self.__extract_image_files(file_path, os.path.join(_EXTRACTED_IMAGE_PATH, self.__image_file_name))
            return self.__scan_image_files(os.path.join(_EXTRACTED_IMAGE_PATH, self.__image_file_name), "Image")
        except Exception as e:
            error = "Request for image: " + file_path + " " + str(e)
            return DockerImageScanResponse(verdict="N/A", error=error)

    def __extract_image_files(self, file_path, extracted_path):
        if os.path.isdir(extracted_path):
            return
        print(str(datetime.now()) + " - Extracting " + file_path)
        try:
            with tarfile.open(file_path, 'r') as tar:
                for file_ in tar:
                    if not file_.islnk() and not file_.issym():
                        tar.extract(member=file_, path=extracted_path)

                # Extract nested tar files
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith('.tar'):
                        nested_tar_path = os.path.join(extracted_path, member.name)
                        nested_tar_destination = os.path.join(extracted_path, os.path.splitext(member.name)[0])
                        self.__extract_image_files(nested_tar_path, nested_tar_destination)

                        # Delete the extracted nested tar file
                        while True:
                            try:
                                os.remove(nested_tar_path)
                                break
                            except:
                                time.sleep(1)

        except Exception as e:
            print(str(datetime.now()) + " - Extracting file error: " + str(e))
            self.start_scan()

        print(str(datetime.now()) + " - Extraction finished")

    def __scan_image_files(self, extracted_path, file_type):
        print(str(datetime.now()) + " - Scanning Docker " + file_type + " files...")
        for subdir, dirs, files in os.walk(extracted_path):
            for file in files:
                cur_path_arr = Path(subdir).parts
                if len(cur_path_arr) <= 2:
                    layer_name = _IMAGE_ROOT
                else:
                    layer_name = cur_path_arr[2]
                file_path = os.path.join(subdir, file)
                response = self.__hard_coded_cred_engine.credentials_scan(file_path)
                if response[0] == "VULNERABLE":
                    self.__verdict = "VULNERABLE"
                    self.__indications_list.append(response[1])
                    self.__sources_list.append(response[2])
                    self.__get_layer_metadata(layer_name)

        return DockerImageScanResponse(self.__verdict, self.__indications_list, self.__sources_list,
                                       self.__layer_metadata)

    def __get_layer_metadata(self, layer_name):
        if layer_name == _IMAGE_ROOT:
            self.__layer_metadata.append(DockerImageLayerMetadata(layer_name, "N/A", "N/A", "N/A", "N/A"))
            return
        with open(os.path.join(_EXTRACTED_IMAGE_PATH, self.__image_file_name, layer_name, "JSON")) as layer_file:
            layer_data = json.load(layer_file)
            parent_metadata = "N/A"
            if "parent" in layer_data:
                parent_metadata = layer_data["parent"]
            container_metadata = "N/A"
            if "container" in layer_data:
                container_metadata = layer_data["container"]
            self.__layer_metadata.append(DockerImageLayerMetadata(layer_data['id'], parent_metadata,
                                                                  layer_data['created'], container_metadata,
                                                                  layer_data['container_config']))

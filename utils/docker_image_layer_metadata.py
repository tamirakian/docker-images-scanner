from dataclasses import dataclass


@dataclass
class DockerImageLayerMetadata:
    """A class used to store docker image layer metadata"""
    layer_id: str
    parent: str
    created: str
    container: str
    container_config: object

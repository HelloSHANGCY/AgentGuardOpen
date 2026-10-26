import yaml
from transformers import AutoModel


def load_model(path):
    model = AutoModel.from_pretrained(path, trust_remote_code=True)
    config = yaml.load(open(path, encoding="utf-8"))
    return model, config

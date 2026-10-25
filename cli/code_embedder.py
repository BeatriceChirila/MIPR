"""Frozen pre-trained code encoder wrapped as a scikit-learn transformer."""
import hashlib
import os
import pickle
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import normalize

_ENCODERS = {}
CACHE_FILE = "emb_cache.pkl"
_CACHE = pickle.load(open(CACHE_FILE, "rb")) if os.path.exists(CACHE_FILE) else {}


class CodeEmbedder(BaseEstimator, TransformerMixin):
    def __init__(self, model_name="microsoft/unixcoder-base", max_length=128, batch_size=32):
        self.model_name = model_name
        self.max_length = max_length
        self.batch_size = batch_size

    def fit(self, X, y=None):
        return self

    def _load(self):
        if self.model_name not in _ENCODERS:
            import torch
            from transformers import AutoModel, AutoTokenizer
            dev = "cuda" if torch.cuda.is_available() else "cpu"
            tok = AutoTokenizer.from_pretrained(self.model_name)
            enc = AutoModel.from_pretrained(self.model_name).to(dev).eval()
            _ENCODERS[self.model_name] = (tok, enc, dev)
        return _ENCODERS[self.model_name]

    def _key(self, text):
        return hashlib.md5(f"{self.model_name}|{self.max_length}|{text}".encode()).hexdigest()

    def transform(self, X):
        import torch
        texts = [str(t) for t in X]
        todo = list(dict.fromkeys(t for t in texts if self._key(t) not in _CACHE))
        if todo:
            tok, enc, dev = self._load()
            # sort by length so batches have little padding (faster)
            todo.sort(key=len)
            with torch.no_grad():
                for i in range(0, len(todo), self.batch_size):
                    batch = todo[i:i + self.batch_size]
                    b = tok(batch, padding=True, truncation=True,
                            max_length=self.max_length, return_tensors="pt").to(dev)
                    h = enc(**b).last_hidden_state
                    m = b["attention_mask"].unsqueeze(-1)
                    v = ((h * m).sum(1) / m.sum(1)).cpu().numpy()
                    for t, vec in zip(batch, v):
                        _CACHE[self._key(t)] = vec.astype(np.float32)
                    if (i // self.batch_size) % 50 == 0:
                        print(f"   embedded {i + len(batch)}/{len(todo)}", flush=True)
            with open(CACHE_FILE, "wb") as fh:
                pickle.dump(_CACHE, fh)
        return normalize(np.vstack([_CACHE[self._key(t)] for t in texts]))
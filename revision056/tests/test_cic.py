import importlib.util
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import numpy as np
import pytest

P = Path(__file__).resolve().parents[1] / 'cic/run_cic.py'
spec = importlib.util.spec_from_file_location('cic056_test', P)
cic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cic)


def test_attack_labels_are_not_keyword_guesses():
    assert len(cic.ATTACKS) == 33
    values = ['BenignTraffic', 'Mirai-greeth_flood', 'DNS_Spoofing', 'XSS', 'Recon-OSScan', 'DictionaryBruteForce']
    assert cic.labels(values).tolist() == [0, 1, 1, 1, 1, 1]
    with pytest.raises(ValueError):
        cic.labels(['unknown_attack', 'BenignTraffic'])


def test_identical_admitted_vectors_cannot_leak_between_roles():
    rng = np.random.default_rng(42)
    x = rng.uniform(0, 1e5, (1000, 8)).astype(np.float32)
    x[0] = 0
    z = x.copy(); z[0] = -0.
    a = cic.role_indices(x)
    assert set(a) == set(range(5))
    assert np.array_equal(a, cic.role_indices(z))
    assert np.array_equal(np.tile(a, 2), cic.role_indices(np.concatenate([x, z])))
    assert np.array_equal(a[::-1], cic.role_indices(x[::-1]))
    with pytest.raises(ValueError):
        cic.role_indices(np.full((1, 8), np.inf))


def test_weighting_preserves_conflicting_labels_and_counts(tmp_path):
    db = sqlite3.connect(tmp_path / 'test_vectors.sqlite')
    db.executescript('CREATE TABLE vectors(key BLOB PRIMARY KEY,n0 INTEGER,n1 INTEGER);'
                    'CREATE TABLE groups(key BLOB,label INTEGER,kind TEXT,n INTEGER);')
    for value, n0, n1 in [(0., 100, 30), (1., 1, 2)]:
        key = np.full(8, value, dtype='<f4').tobytes()
        db.execute('INSERT INTO vectors VALUES(?,?,?)', (key, n0, n1))
        db.executemany('INSERT INTO groups VALUES(?,?,?,?)', [(key, 0, 'BenignTraffic', n0), (key, 1, 'XSS', n1)])
    db.commit(); db.close()
    def predict(model, raw):
        y = np.ones(len(raw), np.uint8) if model == 'A' else (raw[:, 0] > 0).astype(np.uint8)
        return y.astype(np.float32), y
    fake = SimpleNamespace(family_of=lambda n: 'lr', predict=predict)
    unique, rows = cic.evaluate({'A_lr': 'A', 'B_lr': 'B'}, tmp_path, fake)
    assert unique == 2
    rows = {(r['model'], r['weighting']): r for r in rows}
    b = rows['B_lr', 'rows']
    assert [b[k] for k in ('tn', 'fp', 'fn', 'tp')] == [100., 1., 30., 2.]
    assert rows['A_lr', 'rows']['decision_disagreement'] == pytest.approx(130 / 133)
    assert rows['A_lr', 'vector_balanced']['decision_disagreement'] == pytest.approx(.5)
    assert rows['A_lr', 'frequency_cap100']['decision_disagreement'] == pytest.approx(100 / 103)
    assert rows['B_lr', 'vector_balanced']['recall'] == pytest.approx((2/3) / (30/130 + 2/3))

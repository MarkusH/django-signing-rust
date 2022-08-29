use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::*;

use crate::dumps;

#[pyfunction]
#[pyo3(name = "dumps")]
fn dumps_py(
    py: Python,
    obj: PyObject,
    key: &[u8],
    salt: &[u8],
    compress: bool,
) -> pyo3::PyResult<String> {
    match to_serde_value(py, &obj) {
        Ok(obj) => Ok(dumps(obj, key, salt, compress)),
        Err(e) => Err(e),
    }
}

#[pymodule]
#[pyo3(name = "django_signing")]
fn django_signing_py(_py: Python, m: &PyModule) -> pyo3::PyResult<()> {
    m.add_function(wrap_pyfunction!(dumps_py, m)?)?;
    Ok(())
}

// https://github.com/mozilla-services/python-canonicaljson-rs/blob/b5d3177c3fe03a0b81fb0fdf742d012dc8ee7b3f/src/lib.rs#L87-L167
fn to_serde_value(py: Python, obj: &PyObject) -> PyResult<serde_json::Value> {
    macro_rules! return_cast {
        ($t:ty, $f:expr) => {
            if let Ok(val) = obj.cast_as::<$t>(py) {
                return $f(val);
            }
        };
    }

    macro_rules! return_to_value {
        ($t:ty, $tn:literal) => {
            if let Ok(val) = obj.extract::<$t>(py) {
                return serde_json::value::to_value(val)
                    .map_err(|error| PyTypeError::new_err(format!("{}: {}", $tn, error)));
            }
        };
    }

    if obj.as_ref(py).eq(&py.None())? {
        return Ok(serde_json::Value::Null);
    }

    return_to_value!(String, "string");
    return_to_value!(bool, "bool");
    return_to_value!(u64, "u64");
    return_to_value!(i64, "i64");

    return_cast!(PyDict, |x: &PyDict| {
        let mut map = serde_json::Map::new();
        for (key_obj, value) in x.iter() {
            let key = if key_obj.eq(py.None().as_ref(py))? {
                Ok("null".to_string())
            } else if let Ok(val) = key_obj.extract::<bool>() {
                Ok(if val {
                    "true".to_string()
                } else {
                    "false".to_string()
                })
            } else if let Ok(val) = key_obj.str() {
                Ok(val.to_string())
            } else {
                Err(PyTypeError::new_err(
                    key_obj
                        .to_object(py)
                        .as_ref(py)
                        .get_type()
                        .name()?
                        .to_string(),
                ))
            };
            map.insert(key?, to_serde_value(py, &value.to_object(py))?);
        }
        Ok(serde_json::Value::Object(map))
    });

    return_cast!(PyList, |x: &PyList| {
        Ok(serde_json::Value::Array(
            match x
                .iter()
                .map(|x| to_serde_value(py, &x.to_object(py)))
                .collect()
            {
                Ok(v) => v,
                Err(e) => return Err(PyValueError::new_err(format!("{}", e))),
            },
        ))
    });

    return_cast!(PyTuple, |x: &PyTuple| {
        Ok(serde_json::Value::Array(
            match x
                .iter()
                .map(|x| to_serde_value(py, &x.to_object(py)))
                .collect()
            {
                Ok(v) => v,
                Err(e) => return Err(PyValueError::new_err(format!("{}", e))),
            },
        ))
    });

    return_cast!(PyFloat, |x: &PyFloat| {
        match serde_json::Number::from_f64(x.value()) {
            Some(n) => Ok(serde_json::Value::Number(n)),
            None => Err(PyTypeError::new_err(x.to_object(py))),
        }
    });

    // At this point we can't cast it, set up the error object
    Err(PyTypeError::new_err(format!(
        "Cannot cast type {} to JSON.",
        obj.as_ref(py).get_type().repr()?
    )))
}

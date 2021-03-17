# AuraBorealis: 

## About

AuraBorealis is a Flask-based webapp for visualizing security vulnerability warnings and information for Python packages. It is a front-end wrapper around data collected from scanning the Python package registry via [Aura](https://github.com/SourceCode-AI/aura). The current tool is a proof-of-concept, and includes some live Aura data, as well as some mockup data for demo purposes.

Current features include:

* Scanning the entire python package registry to:
	* List packages with the highest number of security warnings, sorted by [Aura warning type](https://docs.aura.sourcecode.ai/cookbook/misc/detections.html)
	* List packages sorted by the total and unique count of warnings
	* List packages by their overall severity score
	* List packages that have changes in their warnings and/or severity score between two dates

* Displaying security warnings for an individual package, sorted by criticality
* Visualize the line numbers and lines of code in files generating security warnings for a specific package
* Compare two packages or different versions of the same package for security warnings

## Instructions

Make sure you have installed [Flask](https://anaconda.org/anaconda/flask) and [Elastic Search](https://elasticsearch-py.readthedocs.io/en/6.8.2/).

After downloading this repository, go to the root directory and run 
`python app.py` 
Navigate to the URL in your browser that it shows: `http://0.0.0.0:5000/`

## Feature Roadmap

* Compare a package to a *benchmark profile* of packages of similar purpose for security warnings
* Ability to scan an internal package/registry that's not public on PyPI
* Display an analysis of permissions (does this package make a network connection? Does this package require OS-level library permissions?)

## Contact Information

jmeyers@iqt.org

## Related Work

* Our blog post on [secure code reuse](https://www.iqt.org/toward-secure-code-reuse/)
* Our blog post on [typosquatting](https://www.iqt.org/bewear-python-typosquatting-is-about-more-than-typos/) and [preventing typosquatting via pypi-scan](https://www.iqt.org/pypi-scan/)
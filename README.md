# AuraBorealis: Do You Know What's In Your Python Packages?

## About

AuraBorealis is a web application for visualizing anomalous and potentially malicious code in Python package registries. It
uses security audit data produced by scanning the Python Package Index (PyPI) via [Aura](https://github.com/SourceCode-AI/aura), a
static analysis designed for large scale security auditing of Python packages
.
The current tool is a proof-of-concept, and includes some live Aura data, as well as some mockup data for demo purposes.

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

Clone the repository.

`git clone https://github.com/IQTLabs/AuraBorealisApp.git`

Navigate to aura-borealis-flask-app directory.

`cd aura-borealis-flask-app`

Install dependencies.

`pip install requirements.txt`

Run the app.

`python app.py` 

Navigate to the URL `http://0.0.0.0:5000/` via a browser.

## Feature Roadmap

* Compare a package to a *benchmark profile* of packages of similar purpose for security warnings
* Ability to scan an internal package/registry that's not public on PyPI
* Display an analysis of permissions (does this package make a network connection? Does this package require OS-level library permissions?)

## Contact Information

jmeyers@iqt.org (John Speed Meyers, Secure Code Reuse project lead). The lead developer and creator of Aura is Martin Carnogusky of [sourcecode.ai](https://aura.sourcecode.ai/).

## Related Work

* IQT blog post on [secure code reuse](https://www.iqt.org/toward-secure-code-reuse/)
* IQT blog posts on [typosquatting](https://www.iqt.org/bewear-python-typosquatting-is-about-more-than-typos/) and [preventing typosquatting via pypi-scan](https://www.iqt.org/pypi-scan/)
* USENIX article on ["Counting Broken Links: A Quant's View of Software Supply Chain Security"](https://www.usenix.org/system/files/login/articles/login_winter20_17_geer.pdf)
* IQT open source [dataset](https://github.com/IQTLabs/software-supply-chain-compromises) on known software supply chain compromises

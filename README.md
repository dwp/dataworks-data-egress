# dataworks-data-egress

## A repo for dataworks data egress application code

This repo contains Makefile, and Dockerfile to fit the standard pattern.
This repo is a base to create new Docker image repos, adding the githooks submodule, making the repo ready for use.

After cloning this repo, please run:  
`make bootstrap`

## Testing locally

To run the tests, you will need [tox](https://tox.readthedocs.io/en/latest/) installed:

```
$ pip install tox
$ tox
```
Running `tox` from this directory will run all the tests.

Note that there is no requirement to have any AWS connectivity - it is stubbed to avoid incurring any
costs when running the tests.

### Cleaning outputs locally

Running the following will remove all the local files created by tox, in case you need to tidy up:

```
rm -rf build dist .tox
```

# DO NOT USE THIS REPO - MIGRATED TO GITLAB

# dataworks-data-egress

## A repo for dataworks data egress application code

This repo contains Makefile, and Dockerfile to fit the standard pattern.
This repo is a base to create new Docker image repos, adding the githooks submodule, making the repo ready for use.

After cloning this repo, please run:  
`make bootstrap`

## Testing locally

To run the integration tests

```
$ make certificates
$ make integration-tests
```

Note that there is no requirement to have any AWS connectivity - it is stubbed to avoid incurring any
costs when running the tests.

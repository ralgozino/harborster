# harborster

A quick and dirty hack to list from Harbor all the CVEs present in artifacts of a
specific project.

Notice that this program could put some stress on your Harbor instance.

🚧 THIS IS WIP 🚧 

## Usage

This project uses poetry to manage virtual envs and dependencies. Please refer to poetry's documentation on information on how to install it if you don't have it present in your system.

1. Install dependencies in the virtual environment:

```shell
poetry install
```

2. Set the needed environment variables:

```shell
export HARBOR_PROJECT_NAME=myproj HARBOR_HOSTNAME=harbor.myco.io HARBOR_USERNAME=admin HARBOR_PASSWORD=admin
```

3. Run the project:

```shell
poetry run python harborster.py
```



The azureml-core provides core packages, modules, and classes for Azure Machine Learning and includes the following:

- Creating/managing workspaces and experiments, and submitting/accessing model runs and run output/logging.
- Creating/managing Machine learning compute targets and resources
- Models, images and web services.
- Modules supporting data representation for Datastore and Dataset in Azure Machine Learning.
- Azure Machine Learning exception classes.
- Module used internally to prepare the Azure ML SDK for remote environments.

*****************
Setup
*****************
Follow these `instructions <https://docs.microsoft.com/azure/machine-learning/how-to-configure-environment#local>`_ to install the Azure ML SDK on your local machine, create an Azure ML workspace, and set up your notebook environment, which is required for the next step.

Once you have set up your environment, install the Azure ML core package:

.. code-block:: python

  pip install azureml-core





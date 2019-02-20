Community Repository
====================

This is an open repository dedicated to **contributions from the commmunity**.
Here you are able to submit the custom modules that you wrote for your Cuckoo
Sandbox setup and that you want to share with the rest of the community.

We believe that there's high value and potential in the malware research
community to be more transparent and cooperative and this wants to be an
initiative to support it.

We have recently started a [changelog](CHANGELOG.md) with documentation on
recent changes. We expect this to grow overtime!

How to use it
-------------

You will find that all the directories here share the same structure of our
latest Cuckoo Sandbox release. Potentially you could just download the whole
repository and extract it in Cuckoo's root directory, but we suggest you to
manually take care of copying just the modules you are interested in.

Cuckoo also provides an utility to automatically download and install
latest modules. You can do so by running the `cuckoo community` command.

Being a community-driven repository we, as the Cuckoo Sandbox developers,
do not take any responsibility for the validity of the code submitted.
We will try to keep this place in order, but we can't guarantee the
quality of the modules here available and therefore do not provide any
assistance on eventual malfunctions.

Contributing
------------

If you have one or more Signatures you'd like to share, please make a pull
request and we'll take care of it eventually.

Before submitting your request make sure that:
* You take a look at the [community guidelines](https://cuckoo.sh/docs/introduction/community.html)
* Your code is working.
* Your code is unique: don't reinvent the wheel and check whether someone already provided a similar solution.
* Your code is relevant to the project and actually adds some value.
* Your code is placed in the correct directory.

There are many factors that make it easier for us to merge your pull request.
Inclusion of `sample hashes`, before and after results, and tested
environment(s) really help us with evaluating your potential contributions,
and as such make the merge it more quickly.

We take the discretion to approve or reject submissions at our will.

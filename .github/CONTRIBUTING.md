# How to become a contributor and submit your own code

## Contributor License Agreements

We'd love to accept your sample apps and patches! Before we can take them, we
have to jump a couple of legal hurdles.

Please fill out either the individual or corporate Contributor License Agreement
(CLA).

  * If you are an individual writing original source code and you're sure you
    own the intellectual property, then you'll need to sign an [individual CLA].
  * If you work for a company that wants to allow you to contribute your work,
    then you'll need to sign a [corporate CLA].

[individual CLA]: http://code.google.com/legal/individual-cla-v1.0.html
[corporate CLA]: http://code.google.com/legal/corporate-cla-v1.0.html

Follow either of the two links above to access the appropriate CLA and
instructions for how to sign and return it. Once we receive it, we'll be able to
accept your pull requests.

## Issue reporting

* Check that the issue has not already been reported.
* Check that the issue has not already been fixed in the latest code
  (a.k.a. the `main` branch).
* Be clear, concise and precise in your description of the problem.
* Open an issue with a descriptive title and a summary in grammatically correct,
    complete sentences.
* Include any relevant code to the issue summary.

## Pull requests

* Read [how to properly contribute to open source projects on Github][2].
* Fork the project.
* Use a topic/feature branch to easily amend a pull request later, if necessary.
* Write [good commit messages][3].
* Use the same coding conventions as the rest of the project.
* Commit and push until you are happy with your contribution.
* Make sure to add tests for it. This is important so I don't break it
  in a future version unintentionally.
* Please try not to mess with the Rakefile, version, or history. If you want to
  have your own version, or is otherwise necessary, that is fine, but please
  isolate to its own commit so I can cherry-pick around it.
* Make sure the test suite is passing and the code you wrote doesn't produce
  RuboCop offenses.
* [Squash related commits together][5].
* Open a [pull request][4] that relates to *only* one subject with a clear title
  and description in grammatically correct, complete sentences.

[1]: https://github.com/google/google-auth-ruby-library/issues
[2]: http://gun.io/blog/how-to-github-fork-branch-and-pull-request
[3]: http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
[4]: https://help.github.com/articles/using-pull-requests
[5]: http://gitready.com/advanced/2009/02/10/squashing-commits-with-rebase.html

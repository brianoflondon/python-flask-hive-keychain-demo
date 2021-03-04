# How to use Hive Keychain and Python Flask

You can hopefully see a demo of this project at [https://hive-keychain-flask-python.herokuapp.com/](https://hive-keychain-flask-python.herokuapp.com/)

This is all based on the fantastic Flask series of videos by Corey Schafer.

[Full playlist for Corey's Flask Blog](https://www.youtube.com/watch?v=MwZwr5Tvyxo&list=PL-osiE80TeTs4UjLw5MM6OjgkjFeUxCYH)

The base code for this comes from Corey's 6th video in the series:

[Python Flask Tutorial: Full-Featured Web App Part 6 - User Authentication](https://www.youtube.com/watch?v=CSHx6eCkmv0&list=PL-osiE80TeTs4UjLw5MM6OjgkjFeUxCYH&index=6)

And the code is on [GitHub](https://github.com/CoreyMSchafer/code_snippets/tree/master/Python/Flask_Blog/06-Login-Auth)

There's one extra step about creating virtual environments which this video is good for https://www.youtube.com/watch?v=ojzNmvkNfqc


## Adding Hive

Besides the packages which Corey has you install, pretty much all you need for Hive is this:

```pip install beem```

If you look in the various parts you'll be able to see the changes I made to add Hive Keychain. A bit of javascript on the login page, some changes to the User database model and some logic in the routes.py file.

That's it.

I hope this helps future devs getting started to add Hive to their project!
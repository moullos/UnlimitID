from setuptools import setup
 
setup(
    name='UnlimitID',
    packages=['UnlimitID',
              'UnlimitID.IdP',
              'UnlimitID.User'],
    include_package_data=True,
    install_requires=[
        'flask==0.11.1',
        'Flask-OAuthlib',
        'Flask-SQLAlchemy==2.1',
        'petlib',
        'wtforms',
        'Flask-WTF==0.14'
    ],
    tests_require=[
        'pytest'
    ],
)

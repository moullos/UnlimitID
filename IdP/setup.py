from setuptools import setup
 
setup(
    name='IdP',
    packages=['IdP'],
    include_package_data=True,
    install_requires=[
        'flask==0.11.1',
        'Flask-OAuthlib==0.9.4',
        'Flask-SQLAlchemy==2.1'
    ],
    dependency_links=['https://github.com/gdanezis/petlib.git/tarball/master']
)

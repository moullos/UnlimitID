from setuptools import setup
 
setup(
    name='User',
    packages=['User'],
    include_package_data=True,
    install_requires=[
        'flask==0.11.1',
        'Flask-OAuthlib==0.9.4'
    ],
    dependency_links=['https://github.com/gdanezis/petlib.git/tarball/master']
)

from setuptools import setup

setup(
    name='UnlimitID',
    packages=['UnlimitID',
              'UnlimitID.IdP',
              'UnlimitID.User'],
    version='0.1',
    description='An implementation of UnlimitID',
    author='Panagiotis Moullotou',
    author_email='p.moullotou.16@ucl.ac.uk',
    url='https://github.com/moullos/UnlimitID',
    download_url='https://github.com/moullos/UnlimitID/archive/0.1.tar.gz',
    classifiers=[],
    include_package_data=True,
    install_requires=[
        'flask==2.3.2',
        'Flask-OAuthlib',
        'Flask-SQLAlchemy==2.1',
        'petlib',
        'wtforms',
        'Flask-WTF==0.14'
    ],
    tests_require=[
        'pytest', 'tox'
    ],
)

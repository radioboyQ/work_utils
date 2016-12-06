from setuptools import setup

setup(
    name='utils',
    version='0.1',
    packages=['utils', 'utils.commands', 'utils.lib', 'utils.commands'],
    include_package_data=True,
    install_requires=[
        'arrow',
        'click',
        'lxml',
        'numpy',
        'pandas',
        'requests',
        'xlrd',

    ],
    entry_points='''
        [console_scripts]
        utils=utils.cli:cli
    ''',
)
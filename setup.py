from setuptools import setup, find_packages

setup(
    name='ctrail',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Click>=6.7',
        'requests',
        'xmltodict'
    ],
    entry_points='''
        [console_scripts]
        ctrail=ctrail.scripts.ctrail:cli
    ''',

    author='Andrei-Marius Radu',
    author_email='andrei@thendiscard.net',
    description='ctrail can retrieve information (control plane, forwarding plane, etc.) from a Contrail system.',
    license='MIT'
)

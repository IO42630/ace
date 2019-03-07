from setuptools import setup

setup(name='ace-authz',
      version='0.1',
      description='Authentication and Authorization for Constrained Environments',
      url='https://github.com/DurandA/ace',
      author='Urs Gerber',
      author_email='ug.gerber@gmail.com',
      packages=['ace'],
      install_requires=[
          'aiohttp>=3.1.3',
          'aiocoap>=0.3',
          'cbor2==4.1.2.post3',
          'cryptography>=2.2.2',
          'ecdsa>=0.13'
      ],
      zip_safe=False)

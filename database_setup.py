import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()
 
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))    

class School(Base):
    __tablename__ = 'school'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
 
class Field(Base):
    __tablename__ = 'field'


    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(250))
    crhours = Column(Integer)
    crprice = Column(String(8))
    school_id = Column(Integer,ForeignKey('school.id'))
    school = relationship(School)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

#We added this serialize function to be able to send JSON objects in a serializable format
    @property
    def serialize(self):
       
       return {
           'name: ' : self.name,
           'id: ' : self.id,
           'description: ' : self.description,
           'credit hours: ' : self.crhours,
            'credit hour price: ' : self.crprice,
           }
 

engine = create_engine('sqlite:///universityusers.db')
 

Base.metadata.create_all(engine)
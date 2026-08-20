<?php function a(){}function b(){a();}class C{function d(){return b();}}$c=new C();echo $c->d();

?N
??
9
Add
x"T
y"T
z"T"
Ttype:
2	
x
Assign
ref"T?

value"T

output_ref"T?"	
Ttype"
validate_shapebool("
use_lockingbool(?
8
Const
output"dtype"
valuetensor"
dtypetype
.
Identity

input"T
output"T"	
Ttype
b
MergeV2Checkpoints
checkpoint_prefixes
destination_prefix"
delete_old_dirsbool(
<
Mul
x"T
y"T
z"T"
Ttype:
2	?

NoOp
M
Pack
values"T*N
output"T"
Nint(0"	
Ttype"
axisint 
?
ParseExample

serialized	
names
sparse_keys*Nsparse

dense_keys*Ndense
dense_defaults2Tdense
sparse_indices	*Nsparse
sparse_values2sparse_types
sparse_shapes	*Nsparse
dense_values2Tdense"
Nsparseint("
Ndenseint("%
sparse_types
list(type)(:
2	"
Tdense
list(type)(:
2	"
dense_shapeslist(shape)(
C
Placeholder
output"dtype"
dtypetype"
shapeshape:
[
Reshape
tensor"T
shape"Tshape
output"T"	
Ttype"
Tshapetype0:
2	
l
	RestoreV2

prefix
tensor_names
shape_and_slices
tensors2dtypes"
dtypes
list(type)(0
i
SaveV2

prefix
tensor_names
shape_and_slices
tensors2dtypes"
dtypes
list(type)(0
H
ShardedFilename
basename	
shard

num_shards
filename
N

StringJoin
inputs*N

output"
Nint(0"
	separatorstring 
s

VariableV2
ref"dtype?"
shapeshape"
dtypetype"
	containerstring "
shared_namestring ?"serve*	1.1.0-rc22unknown?9
T
a/initial_valueConst*
valueB
 *   ?*
dtype0*
_output_shapes
: 
e
a
VariableV2*
	container *
shape: *
dtype0*
_output_shapes
: *
shared_name 
?
a/AssignAssignaa/initial_value*
T0*
validate_shape(*
_class

loc:@a*
use_locking(*
_output_shapes
: 
L
a/readIdentitya*
T0*
_class

loc:@a*
_output_shapes
: 
T
b/initial_valueConst*
valueB
 *   @*
dtype0*
_output_shapes
: 
e
b
VariableV2*
	container *
shape: *
dtype0*
_output_shapes
: *
shared_name 
?
b/AssignAssignbb/initial_value*
validate_shape(*
_class

loc:@b*
use_locking(*
_output_shapes
: *
T0
L
b/readIdentityb*
T0*
_class

loc:@b*
_output_shapes
: 
T
c/initial_valueConst*
valueB
 *  @@*
dtype0*
_output_shapes
: 
e
c
VariableV2*
	container *
shape: *
dtype0*
_output_shapes
: *
shared_name 
?
c/AssignAssigncc/initial_value*
T0*
validate_shape(*
_class

loc:@c*
use_locking(*
_output_shapes
: 
L
c/readIdentityc*
T0*
_class

loc:@c*
_output_shapes
: 
O

tf_examplePlaceholder*
shape:*
dtype0*
_output_shapes
:
U
ParseExample/ConstConst*
valueB *
dtype0*
_output_shapes
: 
`
ParseExample/key_x2Const*
valueB*    *
dtype0*
_output_shapes
:
d
ParseExample/Reshape/shapeConst*
valueB:*
dtype0*
_output_shapes
:
?
ParseExample/ReshapeReshapeParseExample/key_x2ParseExample/Reshape/shape*
Tshape0*
_output_shapes
:*
T0
b
ParseExample/ParseExample/namesConst*
valueB *
dtype0*
_output_shapes
: 
h
&ParseExample/ParseExample/dense_keys_0Const*
value	B Bx*
dtype0*
_output_shapes
: 
i
&ParseExample/ParseExample/dense_keys_1Const*
value
B Bx2*
dtype0*
_output_shapes
: 
?
ParseExample/ParseExampleParseExample
tf_exampleParseExample/ParseExample/names&ParseExample/ParseExample/dense_keys_0&ParseExample/ParseExample/dense_keys_1ParseExample/ConstParseExample/Reshape*
Ndense*
sparse_types
 *:
_output_shapes(
&:?????????:?????????*
Tdense
2*
dense_shapes
::*
Nsparse 
Z
xIdentityParseExample/ParseExample*'
_output_shapes
:?????????*
T0
G
MulMula/readx*'
_output_shapes
:?????????*
T0
G
yAddMulb/read*'
_output_shapes
:?????????*
T0
I
Mul_1Mula/readx*'
_output_shapes
:?????????*
T0
J
y2AddMul_1c/read*'
_output_shapes
:?????????*
T0
]
x2IdentityParseExample/ParseExample:1*
T0*'
_output_shapes
:?????????
J
Mul_2Mula/readx2*'
_output_shapes
:?????????*
T0
J
y3AddMul_2c/read*'
_output_shapes
:?????????*
T0
i
ConstConst*4
value+B) B#/tmp/original/export/assets/foo.txt*
dtype0*
_output_shapes
: 
e
filename_tensor/initial_valueConst*
valueB Bfoo.txt*
dtype0*
_output_shapes
: 
s
filename_tensor
VariableV2*
	container *
shape: *
dtype0*
_output_shapes
: *
shared_name 
?
filename_tensor/AssignAssignfilename_tensorfilename_tensor/initial_value*
validate_shape(*"
_class
loc:@filename_tensor*
use_locking(*
_output_shapes
: *
T0
v
filename_tensor/readIdentityfilename_tensor*
T0*"
_class
loc:@filename_tensor*
_output_shapes
: 
T
Assign/valueConst*
valueB Bfoo.txt*
dtype0*
_output_shapes
: 
?
AssignAssignfilename_tensorAssign/value*
T0*
validate_shape(*"
_class
loc:@filename_tensor*
use_locking( *
_output_shapes
: 
-
initNoOp	^a/Assign	^b/Assign	^c/Assign
/
init_1NoOp	^a/Assign	^b/Assign	^c/Assign

init_2NoOp

init_all_tablesNoOp
6

group_depsNoOp^init_1^init_2^init_all_tables
*
group_deps_1NoOp^group_deps^Assign
P

save/ConstConst*
valueB Bmodel*
dtype0*
_output_shapes
: 
?
save/StringJoin/inputs_1Const*<
value3B1 B+_temp_54fad5ae87d9453a84cf16e721fe825d/part*
dtype0*
_output_shapes
: 
u
save/StringJoin
StringJoin
save/Constsave/StringJoin/inputs_1*
	separator *
_output_shapes
: *
N
Q
save/num_shardsConst*
value	B :*
dtype0*
_output_shapes
: 
\
save/ShardedFilename/shardConst*
value	B : *
dtype0*
_output_shapes
: 
}
save/ShardedFilenameShardedFilenamesave/StringJoinsave/ShardedFilename/shardsave/num_shards*
_output_shapes
: 
h
save/SaveV2/tensor_namesConst*
valueBBaBbBc*
dtype0*
_output_shapes
:
i
save/SaveV2/shape_and_slicesConst*
valueBB B B *
dtype0*
_output_shapes
:

save/SaveV2SaveV2save/ShardedFilenamesave/SaveV2/tensor_namessave/SaveV2/shape_and_slicesabc*
dtypes
2
?
save/control_dependencyIdentitysave/ShardedFilename^save/SaveV2*
T0*'
_class
loc:@save/ShardedFilename*
_output_shapes
: 
?
+save/MergeV2Checkpoints/checkpoint_prefixesPacksave/ShardedFilename^save/control_dependency*
N*
T0*
_output_shapes
:*

axis 
}
save/MergeV2CheckpointsMergeV2Checkpoints+save/MergeV2Checkpoints/checkpoint_prefixes
save/Const*
delete_old_dirs(
z
save/IdentityIdentity
save/Const^save/control_dependency^save/MergeV2Checkpoints*
_output_shapes
: *
T0
e
save/RestoreV2/tensor_namesConst*
valueBBa*
dtype0*
_output_shapes
:
h
save/RestoreV2/shape_and_slicesConst*
valueB
B *
dtype0*
_output_shapes
:
?
save/RestoreV2	RestoreV2
save/Constsave/RestoreV2/tensor_namessave/RestoreV2/shape_and_slices*
dtypes
2*
_output_shapes
:
?
save/AssignAssignasave/RestoreV2*
validate_shape(*
_class

loc:@a*
use_locking(*
_output_shapes
: *
T0
g
save/RestoreV2_1/tensor_namesConst*
valueBBb*
dtype0*
_output_shapes
:
j
!save/RestoreV2_1/shape_and_slicesConst*
valueB
B *
dtype0*
_output_shapes
:
?
save/RestoreV2_1	RestoreV2
save/Constsave/RestoreV2_1/tensor_names!save/RestoreV2_1/shape_and_slices*
dtypes
2*
_output_shapes
:
?
save/Assign_1Assignbsave/RestoreV2_1*
validate_shape(*
_class

loc:@b*
use_locking(*
_output_shapes
: *
T0
g
save/RestoreV2_2/tensor_namesConst*
valueBBc*
dtype0*
_output_shapes
:
j
!save/RestoreV2_2/shape_and_slicesConst*
valueB
B *
dtype0*
_output_shapes
:
?
save/RestoreV2_2	RestoreV2
save/Constsave/RestoreV2_2/tensor_names!save/RestoreV2_2/shape_and_slices*
dtypes
2*
_output_shapes
:
?
save/Assign_2Assigncsave/RestoreV2_2*
T0*
validate_shape(*
_class

loc:@c*
use_locking(*
_output_shapes
: 
H
save/restore_shardNoOp^save/Assign^save/Assign_1^save/Assign_2
-
save/restore_allNoOp^save/restore_shard"<
save/Const:0save/Identity:0save/restore_all (5 @F8"
asset_filepaths
	
Const:0"j
trainable_variablesSQ

a:0a/Assigna/read:0

b:0b/Assignb/read:0

c:0c/Assignc/read:0"`
	variablesSQ

a:0a/Assigna/read:0

b:0b/Assignb/read:0

c:0c/Assignc/read:0"'
saved_model_main_op

group_deps_1"]
saved_model_assetsG*E
C
+type.googleapis.com/tensorflow.AssetFileDef
	
Const:0foo.txt*u
regress_x_to_yc

inputs
tf_example:0%
outputs
y:0?????????tensorflow/serving/regress*
regress_x2_to_y3k
%
inputs
x2:0?????????&
outputs
y3:0?????????tensorflow/serving/regress*q
serving_default^

x
x:0?????????
y
y:0?????????tensorflow/serving/predict*v
classify_x_to_yc

inputs
tf_example:0$
scores
y:0?????????tensorflow/serving/classify*?
classify_x2_to_y3k
%
inputs
x2:0?????????%
scores
y3:0?????????tensorflow/serving/classify*w
regress_x_to_y2d

inputs
tf_example:0&
outputs
y2:0?????????tensorflow/serving/regress
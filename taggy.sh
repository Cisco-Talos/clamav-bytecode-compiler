#!/bin/sh
set -e

function grafts_repo
{
REPONAME=$1
REFPFX=refs/tags/merge-$REPONAME-
UPSTREAM=$REPONAME-upstream/master
git for-each-ref $REFPFX*  --format='%(refname)' | while read tag_ref
do
	tag_svn_ref=`echo $tag_ref|sed -e s\|$REFPFX\|\|`
	upstream_ref=`git log $UPSTREAM -1 --grep=trunk@$tag_svn_ref --format=format:%H`
	local_ref=`git rev-parse $tag_ref`
	local_ref=`git rev-parse $tag_ref`
	local_parent_ref=`git rev-parse $tag_ref^`
	echo "$local_ref $local_parent_ref $upstream_ref"
done
}

rm -f .git/info/grafts
echo "Creating grafts for llvm-upstream"
grafts_repo llvm >.git/info/grafts
echo "Creating grafts for clang-upstream"
grafts_repo clang >>.git/info/grafts
exit 0
echo "Merging llvm-upstream"
MERGEREV=`git log llvm-upstream/master -1 |grep /trunk@|sed -s 's/.*@\([0-9]*\).*/\1/'`
git merge -s subtree --squash llvm-upstream/master
if test $? -eq 0; then
 git commit && git tag merge-llvm-$MERGEREV
else
    echo "Merge failed: resolve conflicts and run: git tag merge-llvm-$MERGEREV && rm .git/info/grafts"; exit 1;
fi

echo "Merging clang-upstream"
MERGEREV=`git log clang-upstream/master -1 |grep /trunk@|sed -s 's/.*@\([0-9]*\).*/\1/'`
git merge -s subtree --squash clang-upstream/master && git commit || {
echo "Merge failed: resolve conflicts and run: git tag merge-clang-$MERGEREV && rm .git/info/grafts"; exit 1;}
git tag merge-clang-$MERGEREV
rm .git/info/grafts

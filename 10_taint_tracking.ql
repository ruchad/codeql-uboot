/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap(){
        exists(MacroInvocation mi | mi.getMacroName().regexpMatch("ntoh(s|l|ll)") | this = mi.getExpr())
    }
}

class MyConfiguration extends TaintTracking::Configuration{
    MyConfiguration(){this = "MyConfigruation"}

    override predicate isSource(DataFlow::Node source){
        source.asExpr() instanceof NetworkByteSwap
    }

    override predicate isSink(DataFlow::Node sink){
        exists(FunctionCall fc | fc.getTarget().getName()="memcpy" and sink.asExpr() = fc.getArgument(2) )
    }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, MyConfiguration cfg
where
    cfg.hasFlowPath(source, sink)

select sink, source, sink, "Network byte swap flows to memcpy"